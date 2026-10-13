//! In-memory mempool view for the address index: which unconfirmed
//! txs touch which addresses, and which confirmed outputs they spend.
use std::collections::{HashMap, HashSet, VecDeque};

use serde_json::Value;

use super::store::{addr_hash, txid_from_hex, value_to_sats, vout_addresses, AddrHash, Store, Txid};

#[derive(Clone, Debug)]
pub struct MempoolInput {
    pub prev_txid: Txid,
    pub prev_vout: u32,
    pub value: u64,
    pub addresses: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct MempoolOutput {
    pub n: u32,
    pub value: u64,
    pub addresses: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct MempoolTx {
    pub txid: Txid,
    /// Unix time the bridge first saw the tx.
    pub first_seen: u64,
    pub inputs: Vec<MempoolInput>,
    pub outputs: Vec<MempoolOutput>,
    /// Per-address (received, sent).
    pub deltas: HashMap<AddrHash, (u64, u64)>,
}

#[derive(Default)]
pub struct Mempool {
    pub txs: HashMap<Txid, MempoolTx>,
    by_addr: HashMap<AddrHash, HashSet<Txid>>,
    /// Outpoints (txid, vout) spent by some mempool tx.
    spent: HashSet<(Txid, u32)>,
    /// Bumped for every tx added; lets `/watch` clients ask
    /// "what arrived since N".
    seq: u64,
    /// Recent arrivals: (seq, txid, touched addresses), oldest first.
    events: VecDeque<(u64, Txid, Vec<AddrHash>)>,
}

/// Arrival events kept for `/watch`. A client further behind
/// than this is told to resync.
const MAX_EVENTS: usize = 10_000;

impl Mempool {
    pub fn len(&self) -> usize {
        self.txs.len()
    }

    pub fn txids_for(&self, addr: &str) -> Vec<Txid> {
        self.by_addr.get(&addr_hash(addr)).map(|s| s.iter().copied().collect()).unwrap_or_default()
    }

    pub fn touches(&self, addr: &str) -> bool {
        self.by_addr.get(&addr_hash(addr)).is_some_and(|s| !s.is_empty())
    }

    pub fn is_spent(&self, txid: &Txid, vout: u32) -> bool {
        self.spent.contains(&(*txid, vout))
    }

    pub fn seq(&self) -> u64 {
        self.seq
    }

    /// Txids that arrived after `since` and touch one of `addrs`, plus
    /// the current sequence number. `None` when `since` is ahead of us
    /// (bridge restarted) or older than the kept events.
    pub fn events_since(&self, since: u64, addrs: &HashSet<AddrHash>) -> (u64, Option<Vec<Txid>>) {
        if since > self.seq {
            return (self.seq, None);
        }
        if let Some((oldest, _, _)) = self.events.front() {
            if since + 1 < *oldest {
                return (self.seq, None);
            }
        } else if since < self.seq {
            return (self.seq, None);
        }
        let txids = self
            .events
            .iter()
            .rev()
            .take_while(|(s, _, _)| *s > since)
            .filter(|(_, _, touched)| touched.iter().any(|a| addrs.contains(a)))
            .map(|(_, t, _)| *t)
            .collect();
        (self.seq, Some(txids))
    }

    /// Replace the tracked set with `current` (txids from getrawmempool).
    /// `fetch` returns verbose tx JSON for a txid.
    pub fn sync<F>(&mut self, current: &[String], store: &Store, mut fetch: F)
    where
        F: FnMut(&str) -> Option<Value>,
    {
        let current_set: HashSet<Txid> = current.iter().filter_map(|s| txid_from_hex(s)).collect();

        // Drop txs that left the mempool (mined or evicted).
        let gone: Vec<Txid> = self.txs.keys().filter(|t| !current_set.contains(*t)).copied().collect();
        for t in gone {
            self.remove(&t);
        }

        // Add new ones. Parents may arrive after children in the RPC
        // ordering, so retry unresolved txs once at the end.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let mut pending: Vec<(Txid, Value)> = Vec::new();
        for s in current {
            let Some(t) = txid_from_hex(s) else { continue };
            if self.txs.contains_key(&t) {
                continue;
            }
            if let Some(v) = fetch(s) {
                pending.push((t, v));
            }
        }
        for _pass in 0..2 {
            let mut retry = Vec::new();
            for (t, v) in pending {
                match self.build(t, &v, store, now) {
                    Some(tx) => self.insert(tx),
                    None => retry.push((t, v)),
                }
            }
            pending = retry;
            if pending.is_empty() {
                break;
            }
        }
        // Whatever is still unresolved is tracked with partial input info.
        for (t, v) in pending {
            if let Some(tx) = self.build_partial(t, &v, store, now) {
                self.insert(tx);
            }
        }
    }

    fn resolve_prevout(&self, store: &Store, prev: &Txid, n: u32) -> Option<(u64, Vec<String>)> {
        if let Some(ptx) = self.txs.get(prev) {
            return ptx.outputs.iter().find(|o| o.n == n).map(|o| (o.value, o.addresses.clone()));
        }
        store.output(prev, n).ok().flatten().map(|o| (o.value, o.addresses))
    }

    fn build(&self, txid: Txid, v: &Value, store: &Store, now: u64) -> Option<MempoolTx> {
        self.build_inner(txid, v, store, now, false)
    }

    fn build_partial(&self, txid: Txid, v: &Value, store: &Store, now: u64) -> Option<MempoolTx> {
        self.build_inner(txid, v, store, now, true)
    }

    fn build_inner(&self, txid: Txid, v: &Value, store: &Store, now: u64, allow_missing: bool) -> Option<MempoolTx> {
        let mut inputs = Vec::new();
        for input in v["vin"].as_array().map(|a| a.as_slice()).unwrap_or_default() {
            let Some(prev) = input["txid"].as_str().and_then(txid_from_hex) else { continue };
            let n = input["vout"].as_u64().unwrap_or(0) as u32;
            match self.resolve_prevout(store, &prev, n) {
                Some((value, addresses)) => inputs.push(MempoolInput { prev_txid: prev, prev_vout: n, value, addresses }),
                None if allow_missing => {
                    inputs.push(MempoolInput { prev_txid: prev, prev_vout: n, value: 0, addresses: vec![] })
                }
                None => return None,
            }
        }
        let mut outputs = Vec::new();
        for (i, out) in v["vout"].as_array().map(|a| a.as_slice()).unwrap_or_default().iter().enumerate() {
            outputs.push(MempoolOutput {
                n: out["n"].as_u64().unwrap_or(i as u64) as u32,
                value: value_to_sats(&out["value"]),
                addresses: vout_addresses(out),
            });
        }
        let mut deltas: HashMap<AddrHash, (u64, u64)> = HashMap::new();
        for i in &inputs {
            for a in &i.addresses {
                deltas.entry(addr_hash(a)).or_default().1 += i.value;
            }
        }
        for o in &outputs {
            for a in &o.addresses {
                deltas.entry(addr_hash(a)).or_default().0 += o.value;
            }
        }
        Some(MempoolTx { txid, first_seen: now, inputs, outputs, deltas })
    }

    fn insert(&mut self, tx: MempoolTx) {
        for ah in tx.deltas.keys() {
            self.by_addr.entry(*ah).or_default().insert(tx.txid);
        }
        for i in &tx.inputs {
            self.spent.insert((i.prev_txid, i.prev_vout));
        }
        self.seq += 1;
        self.events.push_back((self.seq, tx.txid, tx.deltas.keys().copied().collect()));
        if self.events.len() > MAX_EVENTS {
            self.events.pop_front();
        }
        self.txs.insert(tx.txid, tx);
    }

    fn remove(&mut self, txid: &Txid) {
        if let Some(tx) = self.txs.remove(txid) {
            for ah in tx.deltas.keys() {
                if let Some(set) = self.by_addr.get_mut(ah) {
                    set.remove(txid);
                    if set.is_empty() {
                        self.by_addr.remove(ah);
                    }
                }
            }
            for i in &tx.inputs {
                self.spent.remove(&(i.prev_txid, i.prev_vout));
            }
        }
    }
}

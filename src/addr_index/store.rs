//! Persistent transparent address index (redb).
//!
//! Every output ever created is kept in `OUTS` (so spent inputs can be
//! described without extra RPCs), unspent outputs are mirrored per
//! address in `ADDR_UTXO`, and every (address, tx) pair lands in
//! `ADDR_TX` with the address's received/sent delta for that tx.
//!
//! Addresses are keyed by `sha256(address_string)[..20]` so every
//! address kind the node decodes (P2PKH, P2SH, P2PK, cold-stake
//! staker/owner, exchange) shares one fixed-width key space.
//!
//! Key layouts (all integers in keys are big-endian so byte order ==
//! numeric order):
//!   ADDR_TX    addr(20) | height(4) | txpos(4) | txid(32)  → recv(8) | sent(8)
//!   ADDR_UTXO  addr(20) | txid(32) | vout(4)               → value(8) | height(4) | flags(1)
//!   ADDR_STATS addr(20)                                    → txs(4) | recv(8) | sent(8)
//!   OUTS       txid(32) | vout(4)                          → value(8) | height(4) | flags(1) | n(1) | (len(1) | addr)*
//!   TXS        txid(32)                                    → height(4) | txpos(4)
//!   BLOCKS     height                                      → hash(32) | time(4)
//!   UNDO       height                                      → see `UndoRecord`
use std::collections::HashMap;

use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition, WriteTransaction};
use serde_json::Value;
use sha2::{Digest, Sha256};

const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
const BLOCKS: TableDefinition<u32, &[u8]> = TableDefinition::new("blocks");
const TXS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("txs");
const OUTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("outs");
const ADDR_TX: TableDefinition<&[u8], &[u8]> = TableDefinition::new("addr_tx");
const ADDR_UTXO: TableDefinition<&[u8], &[u8]> = TableDefinition::new("addr_utxo");
const ADDR_STATS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("addr_stats");
const UNDO: TableDefinition<u32, &[u8]> = TableDefinition::new("undo");

/// Schema version — bump to force a reindex on incompatible changes.
const SCHEMA_VERSION: u32 = 1;

pub const FLAG_COINBASE: u8 = 1;
pub const FLAG_COINSTAKE: u8 = 2;

pub type AddrHash = [u8; 20];
pub type Txid = [u8; 32];

pub fn addr_hash(addr: &str) -> AddrHash {
    let digest = Sha256::digest(addr.as_bytes());
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest[..20]);
    out
}

/// Parse a 64-char hex txid (RPC display order) into bytes, same order.
pub fn txid_from_hex(s: &str) -> Option<Txid> {
    if s.len() != 64 {
        return None;
    }
    let v = crate::hex::hex_decode(s)?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Some(out)
}

pub fn txid_to_hex(t: &Txid) -> String {
    let mut s = String::with_capacity(64);
    for b in t {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Coin value as reported by pivxd JSON (float PIV) → satoshis.
pub fn value_to_sats(v: &Value) -> u64 {
    match v {
        Value::Number(n) => {
            let f = n.as_f64().unwrap_or(0.0);
            if f <= 0.0 { 0 } else { (f * 100_000_000.0).round() as u64 }
        }
        Value::String(s) => s.parse::<f64>().map(|f| (f * 100_000_000.0).round() as u64).unwrap_or(0),
        _ => 0,
    }
}

/// Extract the address list of a `vout` entry (deduplicated, in order).
pub fn vout_addresses(vout: &Value) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let spk = &vout["scriptPubKey"];
    if let Some(arr) = spk.get("addresses").and_then(|a| a.as_array()) {
        for a in arr {
            if let Some(s) = a.as_str() {
                if !out.iter().any(|x| x == s) {
                    out.push(s.to_string());
                }
            }
        }
    } else if let Some(s) = spk.get("address").and_then(|a| a.as_str()) {
        out.push(s.to_string());
    }
    out
}

fn outpoint_key(txid: &Txid, vout: u32) -> [u8; 36] {
    let mut k = [0u8; 36];
    k[..32].copy_from_slice(txid);
    k[32..].copy_from_slice(&vout.to_be_bytes());
    k
}

fn addr_tx_key(a: &AddrHash, height: u32, txpos: u32, txid: &Txid) -> [u8; 60] {
    let mut k = [0u8; 60];
    k[..20].copy_from_slice(a);
    k[20..24].copy_from_slice(&height.to_be_bytes());
    k[24..28].copy_from_slice(&txpos.to_be_bytes());
    k[28..].copy_from_slice(txid);
    k
}

fn addr_utxo_key(a: &AddrHash, txid: &Txid, vout: u32) -> [u8; 56] {
    let mut k = [0u8; 56];
    k[..20].copy_from_slice(a);
    k[20..52].copy_from_slice(txid);
    k[52..].copy_from_slice(&vout.to_be_bytes());
    k
}

/// A stored output.
#[derive(Clone, Debug)]
pub struct StoredOut {
    pub value: u64,
    pub height: u32,
    pub flags: u8,
    pub addresses: Vec<String>,
}

impl StoredOut {
    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(14 + self.addresses.iter().map(|a| a.len() + 1).sum::<usize>());
        v.extend_from_slice(&self.value.to_le_bytes());
        v.extend_from_slice(&self.height.to_le_bytes());
        v.push(self.flags);
        v.push(self.addresses.len() as u8);
        for a in &self.addresses {
            v.push(a.len() as u8);
            v.extend_from_slice(a.as_bytes());
        }
        v
    }

    fn decode(b: &[u8]) -> Option<Self> {
        if b.len() < 14 {
            return None;
        }
        let value = u64::from_le_bytes(b[0..8].try_into().ok()?);
        let height = u32::from_le_bytes(b[8..12].try_into().ok()?);
        let flags = b[12];
        let n = b[13] as usize;
        let mut addresses = Vec::with_capacity(n);
        let mut p = 14;
        for _ in 0..n {
            let len = *b.get(p)? as usize;
            p += 1;
            addresses.push(String::from_utf8(b.get(p..p + len)?.to_vec()).ok()?);
            p += len;
        }
        Some(Self { value, height, flags, addresses })
    }
}

/// Aggregated per-address stats (confirmed only).
#[derive(Clone, Copy, Debug, Default)]
pub struct AddrStats {
    pub txs: u32,
    pub received: u64,
    pub sent: u64,
}

impl AddrStats {
    fn encode(&self) -> [u8; 20] {
        let mut v = [0u8; 20];
        v[..4].copy_from_slice(&self.txs.to_le_bytes());
        v[4..12].copy_from_slice(&self.received.to_le_bytes());
        v[12..].copy_from_slice(&self.sent.to_le_bytes());
        v
    }
    fn decode(b: &[u8]) -> Self {
        if b.len() < 20 {
            return Self::default();
        }
        Self {
            txs: u32::from_le_bytes(b[..4].try_into().unwrap()),
            received: u64::from_le_bytes(b[4..12].try_into().unwrap()),
            sent: u64::from_le_bytes(b[12..20].try_into().unwrap()),
        }
    }
}

/// One confirmed history entry for an address.
#[derive(Clone, Copy, Debug)]
pub struct HistoryEntry {
    pub height: u32,
    pub txpos: u32,
    pub txid: Txid,
}

/// A confirmed unspent output for an address.
#[derive(Clone, Copy, Debug)]
pub struct UtxoEntry {
    pub txid: Txid,
    pub vout: u32,
    pub value: u64,
    pub height: u32,
    pub flags: u8,
}

/// Everything needed to roll a block back.
#[derive(Default)]
struct UndoRecord {
    txids: Vec<Txid>,
    created: Vec<[u8; 36]>,
    spent: Vec<[u8; 36]>,
    addr_tx: Vec<[u8; 60]>,
}

impl UndoRecord {
    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        for (list, width) in [
            (self.txids.iter().map(|x| &x[..]).collect::<Vec<_>>(), 32usize),
            (self.created.iter().map(|x| &x[..]).collect::<Vec<_>>(), 36),
            (self.spent.iter().map(|x| &x[..]).collect::<Vec<_>>(), 36),
            (self.addr_tx.iter().map(|x| &x[..]).collect::<Vec<_>>(), 60),
        ] {
            v.extend_from_slice(&(list.len() as u32).to_le_bytes());
            for item in list {
                debug_assert_eq!(item.len(), width);
                v.extend_from_slice(item);
            }
        }
        v
    }

    fn decode(b: &[u8]) -> Option<Self> {
        let mut p = 0usize;
        let mut read_list = |width: usize| -> Option<Vec<Vec<u8>>> {
            let n = u32::from_le_bytes(b.get(p..p + 4)?.try_into().ok()?) as usize;
            p += 4;
            let mut out = Vec::with_capacity(n);
            for _ in 0..n {
                out.push(b.get(p..p + width)?.to_vec());
                p += width;
            }
            Some(out)
        };
        let txids = read_list(32)?.into_iter().map(|x| x.try_into().unwrap()).collect();
        let created = read_list(36)?.into_iter().map(|x| x.try_into().unwrap()).collect();
        let spent = read_list(36)?.into_iter().map(|x| x.try_into().unwrap()).collect();
        let addr_tx = read_list(60)?.into_iter().map(|x| x.try_into().unwrap()).collect();
        Some(Self { txids, created, spent, addr_tx })
    }
}

pub struct Store {
    db: Database,
}

pub type StoreResult<T> = Result<T, String>;

fn e<E: std::fmt::Display>(err: E) -> String {
    err.to_string()
}

impl Store {
    pub fn open(path: &str) -> StoreResult<Self> {
        let db = Database::create(path).map_err(e)?;
        let store = Self { db };
        // Create all tables up front so read transactions never fail
        // with TableDoesNotExist on a fresh database.
        let w = store.db.begin_write().map_err(e)?;
        {
            let mut meta = w.open_table(META).map_err(e)?;
            let existing = meta.get("schema").map_err(e)?.map(|v| v.value().to_vec());
            match existing {
                Some(v) if v.as_slice() != SCHEMA_VERSION.to_le_bytes() => {
                    return Err(format!(
                        "address index schema mismatch at {path} — delete it to reindex"
                    ));
                }
                Some(_) => {}
                None => {
                    meta.insert("schema", &SCHEMA_VERSION.to_le_bytes()[..]).map_err(e)?;
                }
            }
            w.open_table(BLOCKS).map_err(e)?;
            w.open_table(TXS).map_err(e)?;
            w.open_table(OUTS).map_err(e)?;
            w.open_table(ADDR_TX).map_err(e)?;
            w.open_table(ADDR_UTXO).map_err(e)?;
            w.open_table(ADDR_STATS).map_err(e)?;
            w.open_table(UNDO).map_err(e)?;
        }
        w.commit().map_err(e)?;
        Ok(store)
    }

    // ------------------------------------------------------------------
    // Cursor / blocks
    // ------------------------------------------------------------------

    /// Highest fully indexed height, or None when nothing is indexed yet.
    pub fn tip(&self) -> StoreResult<Option<u32>> {
        let r = self.db.begin_read().map_err(e)?;
        let meta = r.open_table(META).map_err(e)?;
        Ok(meta
            .get("tip")
            .map_err(e)?
            .map(|v| u32::from_le_bytes(v.value().try_into().unwrap_or([0; 4]))))
    }

    pub fn block_info(&self, height: u32) -> StoreResult<Option<(String, u32)>> {
        let r = self.db.begin_read().map_err(e)?;
        let t = r.open_table(BLOCKS).map_err(e)?;
        Ok(t.get(height).map_err(e)?.map(|v| {
            let b = v.value();
            let mut h = [0u8; 32];
            h.copy_from_slice(&b[..32]);
            (txid_to_hex(&h), u32::from_le_bytes(b[32..36].try_into().unwrap()))
        }))
    }

    pub fn begin_write(&self) -> StoreResult<WriteTransaction> {
        self.db.begin_write().map_err(e)
    }

    /// Apply one verbose (verbosity 2) block inside an open write
    /// transaction. `keep_undo` controls whether rollback data is
    /// stored (only needed near the tip).
    pub fn apply_block(&self, w: &WriteTransaction, block: &Value, keep_undo: bool) -> StoreResult<()> {
        let height = block["height"].as_u64().ok_or("block without height")? as u32;
        let hash = txid_from_hex(block["hash"].as_str().unwrap_or("")).ok_or("bad block hash")?;
        let time = block["time"].as_u64().unwrap_or(0) as u32;
        let txs = block["tx"].as_array().ok_or("block without tx array (need verbosity 2)")?;

        let mut outs = w.open_table(OUTS).map_err(e)?;
        let mut addr_tx = w.open_table(ADDR_TX).map_err(e)?;
        let mut addr_utxo = w.open_table(ADDR_UTXO).map_err(e)?;
        let mut stats = w.open_table(ADDR_STATS).map_err(e)?;
        let mut txs_t = w.open_table(TXS).map_err(e)?;
        let mut undo = UndoRecord::default();

        // Stats deltas for the whole block, flushed once at the end.
        let mut stat_delta: HashMap<AddrHash, AddrStats> = HashMap::new();

        for (txpos, tx) in txs.iter().enumerate() {
            let txpos = txpos as u32;
            let txid = txid_from_hex(tx["txid"].as_str().unwrap_or("")).ok_or("bad txid")?;
            let vin = tx["vin"].as_array().cloned().unwrap_or_default();
            let vout = tx["vout"].as_array().cloned().unwrap_or_default();
            let is_coinbase = vin.first().map(|v| v.get("coinbase").is_some_and(|c| !c.is_null())).unwrap_or(false);
            let is_coinstake = !is_coinbase
                && !vin.is_empty()
                && vout.len() >= 2
                && value_to_sats(&vout[0]["value"]) == 0
                && vout[0]["scriptPubKey"]["hex"].as_str().unwrap_or("x").is_empty();
            let flags = if is_coinbase { FLAG_COINBASE } else if is_coinstake { FLAG_COINSTAKE } else { 0 };

            // Per-tx address deltas.
            let mut deltas: HashMap<AddrHash, (u64, u64)> = HashMap::new();

            if !is_coinbase {
                for input in &vin {
                    let Some(prev) = input["txid"].as_str().and_then(txid_from_hex) else { continue };
                    let Some(n) = input["vout"].as_u64() else { continue };
                    let op = outpoint_key(&prev, n as u32);
                    let stored = outs.get(&op[..]).map_err(e)?.and_then(|v| StoredOut::decode(v.value()));
                    let Some(stored) = stored else {
                        // Prevout not indexed: only legitimate for
                        // zerocoin-era spends (no transparent prevout).
                        continue;
                    };
                    for a in &stored.addresses {
                        let ah = addr_hash(a);
                        deltas.entry(ah).or_default().1 += stored.value;
                        addr_utxo.remove(&addr_utxo_key(&ah, &prev, n as u32)[..]).map_err(e)?;
                    }
                    undo.spent.push(op);
                }
            }

            for (i, out) in vout.iter().enumerate() {
                let n = out["n"].as_u64().unwrap_or(i as u64) as u32;
                let addresses = vout_addresses(out);
                if addresses.is_empty() {
                    continue;
                }
                let value = value_to_sats(&out["value"]);
                let stored = StoredOut { value, height, flags, addresses };
                let op = outpoint_key(&txid, n);
                outs.insert(&op[..], &stored.encode()[..]).map_err(e)?;
                let mut uv = [0u8; 13];
                uv[..8].copy_from_slice(&value.to_le_bytes());
                uv[8..12].copy_from_slice(&height.to_le_bytes());
                uv[12] = flags;
                for a in &stored.addresses {
                    let ah = addr_hash(a);
                    deltas.entry(ah).or_default().0 += value;
                    addr_utxo.insert(&addr_utxo_key(&ah, &txid, n)[..], &uv[..]).map_err(e)?;
                }
                undo.created.push(op);
            }

            for (ah, (recv, sent)) in &deltas {
                let k = addr_tx_key(ah, height, txpos, &txid);
                let mut v = [0u8; 16];
                v[..8].copy_from_slice(&recv.to_le_bytes());
                v[8..].copy_from_slice(&sent.to_le_bytes());
                addr_tx.insert(&k[..], &v[..]).map_err(e)?;
                undo.addr_tx.push(k);
                let s = stat_delta.entry(*ah).or_default();
                s.txs += 1;
                s.received += recv;
                s.sent += sent;
            }

            let mut tv = [0u8; 8];
            tv[..4].copy_from_slice(&height.to_le_bytes());
            tv[4..].copy_from_slice(&txpos.to_le_bytes());
            txs_t.insert(&txid[..], &tv[..]).map_err(e)?;
            undo.txids.push(txid);
        }

        for (ah, d) in stat_delta {
            let cur = stats.get(&ah[..]).map_err(e)?.map(|v| AddrStats::decode(v.value())).unwrap_or_default();
            let new = AddrStats { txs: cur.txs + d.txs, received: cur.received + d.received, sent: cur.sent + d.sent };
            stats.insert(&ah[..], &new.encode()[..]).map_err(e)?;
        }

        let mut blocks = w.open_table(BLOCKS).map_err(e)?;
        let mut bv = [0u8; 36];
        bv[..32].copy_from_slice(&hash);
        bv[32..].copy_from_slice(&time.to_le_bytes());
        blocks.insert(height, &bv[..]).map_err(e)?;

        if keep_undo {
            let mut u = w.open_table(UNDO).map_err(e)?;
            u.insert(height, &undo.encode()[..]).map_err(e)?;
        }

        let mut meta = w.open_table(META).map_err(e)?;
        meta.insert("tip", &height.to_le_bytes()[..]).map_err(e)?;
        Ok(())
    }

    /// Roll back the current tip block. Fails if no undo data exists
    /// for it (reorg deeper than the undo window).
    pub fn undo_tip(&self) -> StoreResult<u32> {
        let tip = self.tip()?.ok_or("nothing to undo")?;
        let w = self.db.begin_write().map_err(e)?;
        {
            let mut undo_t = w.open_table(UNDO).map_err(e)?;
            let rec = undo_t
                .remove(tip)
                .map_err(e)?
                .and_then(|v| UndoRecord::decode(v.value()))
                .ok_or_else(|| format!("no undo data for height {tip} — reindex required"))?;

            let mut outs = w.open_table(OUTS).map_err(e)?;
            let mut addr_tx = w.open_table(ADDR_TX).map_err(e)?;
            let mut addr_utxo = w.open_table(ADDR_UTXO).map_err(e)?;
            let mut stats = w.open_table(ADDR_STATS).map_err(e)?;
            let mut txs_t = w.open_table(TXS).map_err(e)?;

            // 1. History rows + stats.
            let mut stat_delta: HashMap<AddrHash, AddrStats> = HashMap::new();
            for k in &rec.addr_tx {
                if let Some(v) = addr_tx.remove(&k[..]).map_err(e)? {
                    let b = v.value();
                    let recv = u64::from_le_bytes(b[..8].try_into().unwrap());
                    let sent = u64::from_le_bytes(b[8..16].try_into().unwrap());
                    let mut ah = [0u8; 20];
                    ah.copy_from_slice(&k[..20]);
                    let s = stat_delta.entry(ah).or_default();
                    s.txs += 1;
                    s.received += recv;
                    s.sent += sent;
                }
            }
            for (ah, d) in stat_delta {
                let cur = stats.get(&ah[..]).map_err(e)?.map(|v| AddrStats::decode(v.value())).unwrap_or_default();
                let new = AddrStats {
                    txs: cur.txs.saturating_sub(d.txs),
                    received: cur.received.saturating_sub(d.received),
                    sent: cur.sent.saturating_sub(d.sent),
                };
                if new.txs == 0 {
                    stats.remove(&ah[..]).map_err(e)?;
                } else {
                    stats.insert(&ah[..], &new.encode()[..]).map_err(e)?;
                }
            }

            // 2. Outputs created in this block disappear entirely.
            for op in &rec.created {
                if let Some(v) = outs.remove(&op[..]).map_err(e)? {
                    if let Some(s) = StoredOut::decode(v.value()) {
                        let txid: Txid = op[..32].try_into().unwrap();
                        let n = u32::from_be_bytes(op[32..].try_into().unwrap());
                        for a in &s.addresses {
                            addr_utxo.remove(&addr_utxo_key(&addr_hash(a), &txid, n)[..]).map_err(e)?;
                        }
                    }
                }
            }

            // 3. Outputs spent in this block become unspent again.
            for op in &rec.spent {
                let stored = outs.get(&op[..]).map_err(e)?.and_then(|v| StoredOut::decode(v.value()));
                if let Some(s) = stored {
                    let txid: Txid = op[..32].try_into().unwrap();
                    let n = u32::from_be_bytes(op[32..].try_into().unwrap());
                    let mut uv = [0u8; 13];
                    uv[..8].copy_from_slice(&s.value.to_le_bytes());
                    uv[8..12].copy_from_slice(&s.height.to_le_bytes());
                    uv[12] = s.flags;
                    for a in &s.addresses {
                        addr_utxo.insert(&addr_utxo_key(&addr_hash(a), &txid, n)[..], &uv[..]).map_err(e)?;
                    }
                }
            }

            for t in &rec.txids {
                txs_t.remove(&t[..]).map_err(e)?;
            }

            let mut blocks = w.open_table(BLOCKS).map_err(e)?;
            blocks.remove(tip).map_err(e)?;
            let mut meta = w.open_table(META).map_err(e)?;
            if tip == 0 {
                meta.remove("tip").map_err(e)?;
            } else {
                meta.insert("tip", &(tip - 1).to_le_bytes()[..]).map_err(e)?;
            }
        }
        w.commit().map_err(e)?;
        Ok(tip)
    }

    /// Drop undo records below `min_height`.
    pub fn prune_undo(&self, w: &WriteTransaction, min_height: u32) -> StoreResult<()> {
        let mut u = w.open_table(UNDO).map_err(e)?;
        let old: Vec<u32> = u
            .range(..min_height)
            .map_err(e)?
            .filter_map(|r| r.ok().map(|(k, _)| k.value()))
            .collect();
        for h in old {
            u.remove(h).map_err(e)?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------

    pub fn stats(&self, addr: &str) -> StoreResult<AddrStats> {
        let r = self.db.begin_read().map_err(e)?;
        let t = r.open_table(ADDR_STATS).map_err(e)?;
        Ok(t.get(&addr_hash(addr)[..]).map_err(e)?.map(|v| AddrStats::decode(v.value())).unwrap_or_default())
    }

    pub fn is_used(&self, addr: &str) -> StoreResult<bool> {
        Ok(self.stats(addr)?.txs > 0)
    }

    /// Confirmed history of `addr` within `[from, to]` heights, ascending.
    pub fn history(&self, addr: &str, from: u32, to: u32) -> StoreResult<Vec<HistoryEntry>> {
        let ah = addr_hash(addr);
        let lo = addr_tx_key(&ah, from, 0, &[0u8; 32]);
        let hi = addr_tx_key(&ah, to, u32::MAX, &[0xffu8; 32]);
        let r = self.db.begin_read().map_err(e)?;
        let t = r.open_table(ADDR_TX).map_err(e)?;
        let mut out = Vec::new();
        for item in t.range(&lo[..]..=&hi[..]).map_err(e)? {
            let (k, _) = item.map_err(e)?;
            let k = k.value();
            out.push(HistoryEntry {
                height: u32::from_be_bytes(k[20..24].try_into().unwrap()),
                txpos: u32::from_be_bytes(k[24..28].try_into().unwrap()),
                txid: k[28..60].try_into().unwrap(),
            });
        }
        Ok(out)
    }

    pub fn utxos(&self, addr: &str) -> StoreResult<Vec<UtxoEntry>> {
        let ah = addr_hash(addr);
        let mut lo = [0u8; 56];
        lo[..20].copy_from_slice(&ah);
        let mut hi = [0xffu8; 56];
        hi[..20].copy_from_slice(&ah);
        let r = self.db.begin_read().map_err(e)?;
        let t = r.open_table(ADDR_UTXO).map_err(e)?;
        let mut out = Vec::new();
        for item in t.range(&lo[..]..=&hi[..]).map_err(e)? {
            let (k, v) = item.map_err(e)?;
            let k = k.value();
            let v = v.value();
            out.push(UtxoEntry {
                txid: k[20..52].try_into().unwrap(),
                vout: u32::from_be_bytes(k[52..56].try_into().unwrap()),
                value: u64::from_le_bytes(v[..8].try_into().unwrap()),
                height: u32::from_le_bytes(v[8..12].try_into().unwrap()),
                flags: v[12],
            });
        }
        Ok(out)
    }

    pub fn output(&self, txid: &Txid, vout: u32) -> StoreResult<Option<StoredOut>> {
        let r = self.db.begin_read().map_err(e)?;
        let t = r.open_table(OUTS).map_err(e)?;
        Ok(t.get(&outpoint_key(txid, vout)[..]).map_err(e)?.and_then(|v| StoredOut::decode(v.value())))
    }

    /// Whether `txid:vout` is still unspent (confirmed view).
    pub fn is_unspent(&self, txid: &Txid, vout: u32, any_addr: &str) -> StoreResult<bool> {
        let r = self.db.begin_read().map_err(e)?;
        let t = r.open_table(ADDR_UTXO).map_err(e)?;
        Ok(t.get(&addr_utxo_key(&addr_hash(any_addr), txid, vout)[..]).map_err(e)?.is_some())
    }

    pub fn tx_location(&self, txid: &Txid) -> StoreResult<Option<(u32, u32)>> {
        let r = self.db.begin_read().map_err(e)?;
        let t = r.open_table(TXS).map_err(e)?;
        Ok(t.get(&txid[..]).map_err(e)?.map(|v| {
            let b = v.value();
            (u32::from_le_bytes(b[..4].try_into().unwrap()), u32::from_le_bytes(b[4..8].try_into().unwrap()))
        }))
    }

    pub fn counts(&self) -> StoreResult<(u64, u64, u64)> {
        let r = self.db.begin_read().map_err(e)?;
        Ok((
            r.open_table(TXS).map_err(e)?.len().map_err(e)?,
            r.open_table(OUTS).map_err(e)?.len().map_err(e)?,
            r.open_table(ADDR_STATS).map_err(e)?.len().map_err(e)?,
        ))
    }
}

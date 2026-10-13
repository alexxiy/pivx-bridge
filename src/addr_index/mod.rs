//! Transparent address index (answers in Blockbook's format).
//!
//! Lets light wallets (PIVXie) fetch
//! transparent history, balances and UTXOs for an address or a BIP44
//! account xpub from the bridge itself — no separate Blockbook needed.
//!
//! Runs independently of the shield scanner: its own redb database,
//! its own cursor, its own thread. A failure here never touches the
//! shield stream.
pub mod api;
pub mod mempool;
pub mod store;
pub mod xpub;

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::rpc::RpcClient;
use mempool::Mempool;
use store::{Store, Txid};

/// Blocks behind the node tip for which rollback data is kept.
const UNDO_WINDOW: u32 = 1_000;
/// Parallel block fetchers used during catch-up.
const FETCH_WORKERS: usize = 8;
/// Blocks per write transaction during catch-up.
const CATCHUP_BATCH: u32 = 500;

/// Network-specific encoding parameters, detected from the node.
#[derive(Clone, Debug)]
pub struct NetParams {
    /// `getblockchaininfo.chain`: main / test / regtest
    pub chain: String,
    pub p2pkh_prefix: u8,
    pub bip44_coin_type: u32,
}

impl NetParams {
    pub fn from_chain(chain: &str) -> Self {
        match chain {
            "main" => Self { chain: chain.into(), p2pkh_prefix: 30, bip44_coin_type: 119 },
            _ => Self { chain: chain.into(), p2pkh_prefix: 139, bip44_coin_type: 1 },
        }
    }
}

/// Small LRU for verbose tx JSON (confirmed txs are immutable).
pub struct TxCache {
    map: HashMap<Txid, Value>,
    order: VecDeque<Txid>,
    cap: usize,
}

impl TxCache {
    fn new(cap: usize) -> Self {
        Self { map: HashMap::new(), order: VecDeque::new(), cap }
    }
    pub fn get(&self, t: &Txid) -> Option<Value> {
        self.map.get(t).cloned()
    }
    pub fn contains(&self, t: &Txid) -> bool {
        self.map.contains_key(t)
    }
    pub fn put(&mut self, t: Txid, v: Value) {
        if self.map.contains_key(&t) {
            return;
        }
        if self.map.len() >= self.cap {
            if let Some(old) = self.order.pop_front() {
                self.map.remove(&old);
            }
        }
        self.order.push_back(t);
        self.map.insert(t, v);
    }
}

/// Derived-address cache per xpub: chain -> addresses[index].
pub type XpubCache = HashMap<String, [Vec<String>; 2]>;

/// What `/watch` waits on: indexed tip and mempool sequence.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct WatchState {
    pub height: u32,
    pub hash: String,
    pub mempool_seq: u64,
}

pub struct AddrIndex {
    pub label: &'static str,
    pub store: Store,
    pub mempool: RwLock<Mempool>,
    pub rpc: RpcClient,
    pub net: NetParams,
    /// Node tip as last seen by the indexer.
    pub node_tip: AtomicU32,
    pub in_sync: AtomicBool,
    pub tx_cache: Mutex<TxCache>,
    pub xpub_cache: Mutex<XpubCache>,
    /// Published after every indexer pass while in sync.
    pub changes: tokio::sync::watch::Sender<WatchState>,
}

impl AddrIndex {
    pub fn open(label: &'static str, path: &str, rpc_url: &str, user: &str, pass: &str) -> Result<Arc<Self>, String> {
        let rpc = RpcClient::new(rpc_url, user, pass);
        let info = rpc.proxy_call("getblockchaininfo", &[])?;
        let chain = info["chain"].as_str().unwrap_or("main").to_string();
        let store = Store::open(path)?;
        let tip = store.tip()?;
        let initial = WatchState {
            height: tip.unwrap_or(0),
            hash: tip.and_then(|t| store.block_info(t).ok().flatten()).map(|(h, _)| h).unwrap_or_default(),
            mempool_seq: 0,
        };
        eprintln!(
            "  [{label}] Address index: {path} (chain={chain}, indexed tip={})",
            tip.map(|t| t.to_string()).unwrap_or_else(|| "none".into())
        );
        Ok(Arc::new(Self {
            label,
            store,
            mempool: RwLock::new(Mempool::default()),
            rpc,
            net: NetParams::from_chain(&chain),
            node_tip: AtomicU32::new(info["blocks"].as_u64().unwrap_or(0) as u32),
            in_sync: AtomicBool::new(false),
            tx_cache: Mutex::new(TxCache::new(20_000)),
            xpub_cache: Mutex::new(HashMap::new()),
            changes: tokio::sync::watch::Sender::new(initial),
        }))
    }

    pub fn indexed_tip(&self) -> Option<u32> {
        self.store.tip().ok().flatten()
    }

    /// Spawn the indexer thread (catch-up, follow tip, mempool).
    pub fn spawn(self: &Arc<Self>, rpc_url: String, user: String, pass: String) {
        let idx = self.clone();
        std::thread::Builder::new()
            .name(format!("addr-index-{}", self.label))
            .spawn(move || {
                let rpc = RpcClient::new(&rpc_url, &user, &pass);
                loop {
                    if let Err(e) = idx.sync_blocks(&rpc_url, &user, &pass, &rpc) {
                        eprintln!("  [{}] addr-index: {e} — retrying", idx.label);
                        std::thread::sleep(Duration::from_secs(5));
                        continue;
                    }
                    if idx.in_sync.load(Ordering::Relaxed) {
                        if let Err(e) = idx.sync_mempool(&rpc) {
                            eprintln!("  [{}] addr-index mempool: {e}", idx.label);
                        }
                        idx.publish_changes();
                    }
                    std::thread::sleep(Duration::from_secs(2));
                }
            })
            .expect("spawn addr-index thread");
    }

    /// Bring the index to the node tip, rolling back on reorgs.
    fn sync_blocks(&self, rpc_url: &str, user: &str, pass: &str, rpc: &RpcClient) -> Result<(), String> {
        let node_tip = rpc.get_block_count()? as u32;
        self.node_tip.store(node_tip, Ordering::Relaxed);

        // Reorg handling: compare our stored hash at our tip with the
        // node's; we store every block hash so the fork is exact.
        while let Some(tip) = self.store.tip()? {
            let stored = self.store.block_info(tip)?.map(|(h, _)| h).unwrap_or_default();
            let on_chain = if tip <= node_tip { rpc.get_block_hash(tip).ok() } else { None };
            if on_chain.as_deref() == Some(stored.as_str()) {
                break;
            }
            let undone = self.store.undo_tip()?;
            self.tx_cache.lock().unwrap().map.clear();
            eprintln!("  [{}] addr-index: reorg — rolled back block {undone}", self.label);
        }

        let from = self.store.tip()?.map(|t| t + 1).unwrap_or(0);
        if from > node_tip {
            self.in_sync.store(true, Ordering::Relaxed);
            return Ok(());
        }
        let behind = node_tip - from + 1;
        if behind > 10 {
            self.in_sync.store(false, Ordering::Relaxed);
            eprintln!("  [{}] addr-index: catching up {from}..{node_tip} ({behind} blocks)", self.label);
        }
        self.catch_up(rpc_url, user, pass, from, node_tip)?;
        self.in_sync.store(self.store.tip()? == Some(node_tip), Ordering::Relaxed);
        Ok(())
    }

    fn catch_up(&self, rpc_url: &str, user: &str, pass: &str, from: u32, to: u32) -> Result<(), String> {
        let count = to - from + 1;
        let workers = if count > 50 { FETCH_WORKERS } else { 1 };
        let next = Arc::new(AtomicU32::new(from));
        let stop = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::sync_channel::<(u32, Result<Value, String>)>(256);
        let mut handles = Vec::new();
        for _ in 0..workers {
            let next = next.clone();
            let stop = stop.clone();
            let tx = tx.clone();
            let (u, us, p) = (rpc_url.to_string(), user.to_string(), pass.to_string());
            handles.push(std::thread::spawn(move || {
                let rpc = RpcClient::new(&u, &us, &p);
                loop {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let h = next.fetch_add(1, Ordering::SeqCst);
                    if h > to {
                        break;
                    }
                    let mut res = Err(String::new());
                    for attempt in 0..3 {
                        res = rpc.get_block_hash(h).and_then(|hash| rpc.get_block(&hash, 2));
                        if res.is_ok() {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(500 * (attempt + 1)));
                    }
                    if tx.send((h, res)).is_err() {
                        break;
                    }
                }
            }));
        }
        drop(tx);

        let mut prev_hash: Option<String> = if from == 0 {
            None
        } else {
            self.store.block_info(from - 1)?.map(|(h, _)| h)
        };
        let mut buffer: BTreeMap<u32, Result<Value, String>> = BTreeMap::new();
        let mut expect = from;
        let mut w = self.store.begin_write()?;
        let mut in_txn = 0u32;
        let started = Instant::now();
        let mut last_log = Instant::now();
        let near_tip = |h: u32| h + UNDO_WINDOW > to;
        let mut result = Ok(());

        'outer: for (h, r) in rx.iter() {
            buffer.insert(h, r);
            while let Some(r) = buffer.remove(&expect) {
                let block = match r {
                    Ok(b) => b,
                    Err(e) => {
                        result = Err(format!("fetch block {expect}: {e}"));
                        break 'outer;
                    }
                };
                if let Some(ph) = &prev_hash {
                    if block["previousblockhash"].as_str() != Some(ph.as_str()) {
                        // Chain moved under us — stop; the next pass
                        // runs reorg detection from the committed tip.
                        result = Err(format!("chain changed at {expect} during catch-up"));
                        break 'outer;
                    }
                }
                if let Err(e) = self.store.apply_block(&w, &block, near_tip(expect)) {
                    result = Err(format!("apply block {expect}: {e}"));
                    break 'outer;
                }
                prev_hash = block["hash"].as_str().map(|s| s.to_string());
                expect += 1;
                in_txn += 1;
                let batch = if near_tip(expect) { 1 } else { CATCHUP_BATCH };
                if in_txn >= batch {
                    if expect.is_multiple_of(100) {
                        self.store.prune_undo(&w, to.saturating_sub(UNDO_WINDOW))?;
                    }
                    w.commit().map_err(|e| e.to_string())?;
                    w = self.store.begin_write()?;
                    in_txn = 0;
                }
                if last_log.elapsed() > Duration::from_secs(30) {
                    let done = expect - from;
                    let rate = done as f64 / started.elapsed().as_secs_f64().max(0.001);
                    let eta = (to + 1 - expect) as f64 / rate.max(0.001);
                    eprintln!(
                        "  [{}] addr-index: {}/{} ({rate:.0} blk/s, ETA {:.0} min)",
                        self.label,
                        expect - 1,
                        to,
                        eta / 60.0
                    );
                    last_log = Instant::now();
                }
            }
        }
        // Abort outstanding fetchers before committing.
        stop.store(true, Ordering::SeqCst);
        drop(rx);
        if in_txn > 0 {
            w.commit().map_err(|e| e.to_string())?;
        } else {
            w.abort().map_err(|e| e.to_string())?;
        }
        for h in handles {
            let _ = h.join();
        }
        if count > 10 && result.is_ok() {
            eprintln!(
                "  [{}] addr-index: indexed {count} blocks in {:.1}s",
                self.label,
                started.elapsed().as_secs_f64()
            );
        }
        result
    }

    /// Wake `/watch` waiters if the tip or mempool moved.
    fn publish_changes(&self) {
        let Some(height) = self.indexed_tip() else { return };
        let hash = self.store.block_info(height).ok().flatten().map(|(h, _)| h).unwrap_or_default();
        let state = WatchState { height, hash, mempool_seq: self.mempool.read().unwrap().seq() };
        self.changes.send_if_modified(|s| {
            if *s == state {
                return false;
            }
            *s = state;
            true
        });
    }

    fn sync_mempool(&self, rpc: &RpcClient) -> Result<(), String> {
        let list = rpc.proxy_call("getrawmempool", &[])?;
        let txids: Vec<String> = list
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
            .unwrap_or_default();
        // Fetch new txs without holding the lock.
        let unknown: Vec<String> = {
            let mp = self.mempool.read().unwrap();
            txids
                .iter()
                .filter(|t| store::txid_from_hex(t).is_some_and(|b| !mp.txs.contains_key(&b)))
                .cloned()
                .collect()
        };
        let mut fetched: HashMap<String, Value> = HashMap::new();
        for t in unknown {
            if let Ok(v) = rpc.get_raw_transaction(&t, true) {
                fetched.insert(t, v);
            }
        }
        let mut mp = self.mempool.write().unwrap();
        mp.sync(&txids, &self.store, |t| fetched.remove(t));
        Ok(())
    }
}

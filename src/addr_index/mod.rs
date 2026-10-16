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

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use crate::fetch::Fetcher;
use crate::rpc::RpcClient;
use crate::shield_sync::RpcConfig;
use crate::shutdown;
use mempool::Mempool;
use store::{IndexBlock, Store, Txid};

/// Blocks behind the node tip for which rollback data is kept.
const UNDO_WINDOW: u32 = 1_000;
/// Parallel block fetchers used during catch-up (see the shield indexer's
/// FETCH_WORKERS for why 4).
const FETCH_WORKERS: usize = 4;
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

/// Recent verbose transactions from the node, trimmed to what the API
/// reads of them (`api::trim_tx`), oldest dropped first. A transaction
/// never changes, so entries stay valid across reorgs.
pub struct TxCache {
    map: HashMap<Txid, (Arc<Value>, usize)>,
    order: VecDeque<Txid>,
    /// Estimated bytes held.
    bytes: usize,
}

impl TxCache {
    const MAX_TXS: usize = 20_000;
    const MAX_BYTES: usize = 64 << 20;

    fn new() -> Self {
        Self { map: HashMap::new(), order: VecDeque::new(), bytes: 0 }
    }
    pub fn get(&self, t: &Txid) -> Option<Arc<Value>> {
        self.map.get(t).map(|(v, _)| v.clone())
    }
    pub fn contains(&self, t: &Txid) -> bool {
        self.map.contains_key(t)
    }
    /// Adds `t`, of about `size` bytes.
    pub fn put(&mut self, t: Txid, v: Arc<Value>, size: usize) {
        if self.map.contains_key(&t) {
            return;
        }
        self.order.push_back(t);
        self.map.insert(t, (v, size));
        self.bytes += size;
        while self.map.len() > Self::MAX_TXS || self.bytes > Self::MAX_BYTES {
            let Some(old) = self.order.pop_front() else { break };
            if let Some((_, n)) = self.map.remove(&old) {
                self.bytes -= n;
            }
        }
    }
}

/// Recent xpub histories (txids, newest first), each valid for the index
/// tip and mempool sequence it was read at.
pub struct HistoryCache {
    entries: VecDeque<(HistoryKey, HistoryVersion, Arc<Vec<Txid>>)>,
}

/// (xpub, from, to, gap): a larger gap may find more used addresses.
pub type HistoryKey = (String, u32, Option<u32>, u32);
/// (indexed tip, mempool sequence)
pub type HistoryVersion = (Option<u32>, u64);

impl HistoryCache {
    const CAP: usize = 16;

    pub fn get(&self, key: &HistoryKey, version: HistoryVersion) -> Option<Arc<Vec<Txid>>> {
        self.entries.iter().find(|(k, v, _)| k == key && *v == version).map(|(_, _, t)| t.clone())
    }

    pub fn put(&mut self, key: HistoryKey, version: HistoryVersion, txids: Arc<Vec<Txid>>) {
        self.entries.retain(|(k, _, _)| *k != key);
        if self.entries.len() >= Self::CAP {
            self.entries.pop_front();
        }
        self.entries.push_back((key, version, txids));
    }
}

/// Derived addresses per xpub: chain -> addresses[index].
#[derive(Default)]
pub struct XpubCache {
    pub map: HashMap<String, [Vec<String>; 2]>,
    /// Addresses held, all xpubs together.
    pub addresses: usize,
}

impl XpubCache {
    /// Addresses kept before the cache starts over (about 60 bytes each).
    pub const MAX_ADDRESSES: usize = 200_000;
}

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
    /// The node is behind the index (logged once).
    node_behind: AtomicBool,
    /// Client requests calling the node at once, shared with the
    /// network's other routes (see `api::node_call`).
    pub node_calls: Arc<tokio::sync::Semaphore>,
    pub tx_cache: Mutex<TxCache>,
    pub xpub_cache: Mutex<XpubCache>,
    pub history_cache: Mutex<HistoryCache>,
    /// Published after every indexer pass while in sync.
    pub changes: tokio::sync::watch::Sender<WatchState>,
}

/// How often a node that is still starting is asked again.
const NODE_RETRY: Duration = Duration::from_secs(5);

/// The node's chain (`getblockchaininfo.chain`). Waits while the node is
/// starting (not listening yet, or still loading); other errors, like a
/// wrong RPC password, are returned.
fn node_chain(label: &str, rpc: &RpcClient) -> Result<String, String> {
    loop {
        match rpc.proxy_call("getblockchaininfo", &[]) {
            Ok(info) => return Ok(info["chain"].as_str().unwrap_or("main").to_string()),
            Err(e) if crate::rpc::node_starting(&e) => {
                log::info!("[{label}] addr-index: waiting for the node ({e})");
                if !shutdown::sleep(NODE_RETRY) {
                    return Err("stopping".into());
                }
            }
            Err(e) => return Err(e),
        }
    }
}

impl AddrIndex {
    /// Opens the index at `path`. It records the chain it indexes, so this
    /// doesn't need the node, which may still be starting (after a
    /// reboot). Only an index without a recorded chain asks the node,
    /// waiting for it if needed.
    pub fn open(
        label: &'static str,
        path: &str,
        rpc: &RpcConfig,
        prune: bool,
        node_calls: Arc<tokio::sync::Semaphore>,
    ) -> Result<Arc<Self>, String> {
        let rpc = rpc.client();
        let store = Store::open(path, prune)?;
        let chain = match store.chain()? {
            Some(chain) => chain,
            None => {
                let chain = node_chain(label, &rpc)?;
                store.set_chain(&chain)?;
                chain
            }
        };
        let tip = store.tip()?;
        let initial = WatchState {
            height: tip.unwrap_or(0),
            hash: tip.and_then(|t| store.block_info(t).ok().flatten()).map(|(h, _)| h).unwrap_or_default(),
            mempool_seq: 0,
        };
        log::info!(
            "[{label}] Address index: {path} (chain={chain}, indexed tip={})",
            tip.map(|t| t.to_string()).unwrap_or_else(|| "none".into())
        );
        Ok(Arc::new(Self {
            label,
            store,
            mempool: RwLock::new(Mempool::default()),
            rpc,
            net: NetParams::from_chain(&chain),
            // Set by the indexer's first pass.
            node_tip: AtomicU32::new(0),
            in_sync: AtomicBool::new(false),
            node_behind: AtomicBool::new(false),
            node_calls,
            tx_cache: Mutex::new(TxCache::new()),
            xpub_cache: Mutex::new(XpubCache::default()),
            history_cache: Mutex::new(HistoryCache { entries: VecDeque::new() }),
            changes: tokio::sync::watch::Sender::new(initial),
        }))
    }

    pub fn indexed_tip(&self) -> Option<u32> {
        self.store.tip().ok().flatten()
    }

    /// Spawn the indexer thread (catch-up, follow tip, mempool).
    pub fn spawn(self: &Arc<Self>, cfg: RpcConfig) {
        let idx = self.clone();
        let thread = std::thread::Builder::new()
            .name(format!("addr-index-{}", self.label))
            .spawn(move || {
                let rpc = cfg.client();
                if !idx.check_chain(&rpc) {
                    return;
                }
                while !shutdown::stopping() {
                    if let Err(e) = idx.sync_blocks(&cfg, &rpc) {
                        if !shutdown::stopping() {
                            log::warn!("[{}] addr-index: {e} — retrying", idx.label);
                        }
                        shutdown::sleep(Duration::from_secs(5));
                        continue;
                    }
                    if idx.in_sync.load(Ordering::Relaxed) {
                        if let Err(e) = idx.sync_mempool(&rpc) {
                            log::warn!("[{}] addr-index mempool: {e}", idx.label);
                        }
                        idx.publish_changes();
                    }
                    shutdown::sleep(Duration::from_secs(2));
                }
            })
            .expect("spawn addr-index thread");
        shutdown::register(thread);
    }

    /// Once the node answers, exits the process if it is on another chain
    /// than the index (RPC pointed at the wrong network): indexing on would
    /// roll the whole index back as a reorg. False when stopping first.
    fn check_chain(&self, rpc: &RpcClient) -> bool {
        let chain = loop {
            if shutdown::stopping() {
                return false;
            }
            match node_chain(self.label, rpc) {
                Ok(chain) => break chain,
                Err(e) => {
                    if !shutdown::stopping() {
                        log::warn!("[{}] addr-index: {e} — retrying", self.label);
                    }
                    shutdown::sleep(NODE_RETRY);
                }
            }
        };
        if chain != self.net.chain {
            log::error!(
                "[{}] Address index holds chain {} but the node is on {chain}: fix the RPC settings, \
                 or delete the index to rebuild it for this node",
                self.label, self.net.chain
            );
            std::process::exit(1);
        }
        true
    }

    /// Bring the index to the node tip, rolling back on reorgs.
    fn sync_blocks(&self, cfg: &RpcConfig, rpc: &RpcClient) -> Result<(), String> {
        let node_tip = rpc.get_block_count()? as u32;
        self.node_tip.store(node_tip, Ordering::Relaxed);

        // A node behind us on the same chain (after a -reindex, or one
        // still syncing): wait for it instead of unwinding our blocks.
        let behind = match self.store.tip()? {
            Some(tip) if tip > node_tip => {
                let ours = self.store.block_info(node_tip)?.map(|(h, _)| h);
                ours.is_some() && ours == Some(rpc.get_block_hash(node_tip)?)
            }
            _ => false,
        };
        if behind != self.node_behind.swap(behind, Ordering::Relaxed) {
            if behind {
                log::info!("[{}] The node is at block {node_tip}, behind the address index (block {}): waiting for it", self.label, self.store.tip()?.unwrap_or(0));
            } else if Some(node_tip) >= self.store.tip()? {
                log::info!("[{}] The node caught up with the address index", self.label);
            }
            // Otherwise the node is on another branch: the reorg is logged.
        }
        if behind {
            self.in_sync.store(false, Ordering::Relaxed);
            return Ok(());
        }

        // Reorg handling: compare our stored hash at our tip with the
        // node's; we store every block hash so the fork is exact. An RPC
        // error stops the pass: taken for a different hash, it would undo
        // good blocks.
        let mut undone = None;
        let result = (|| {
            while let Some(tip) = self.store.tip()? {
                let stored = self.store.block_info(tip)?.map(|(h, _)| h).unwrap_or_default();
                let on_chain = if tip <= node_tip { Some(rpc.get_block_hash(tip)?) } else { None };
                if on_chain.as_deref() == Some(stored.as_str()) {
                    break;
                }
                let block = self.store.undo_tip()?;
                undone = Some((block, undone.map_or(block, |(_, top)| top)));
            }
            Ok::<(), String>(())
        })();
        if let Some((low, high)) = undone {
            log::info!("[{}] Address index: reorg, rolled back blocks {low}..{high}", self.label);
        }
        result?;

        let from = self.store.tip()?.map(|t| t + 1).unwrap_or(0);
        if from > node_tip {
            self.in_sync.store(true, Ordering::Relaxed);
            return Ok(());
        }
        let behind = node_tip - from + 1;
        if behind > 10 {
            self.in_sync.store(false, Ordering::Relaxed);
            log::info!("[{}] addr-index: catching up {from}..{node_tip} ({behind} blocks)", self.label);
        }
        self.catch_up(cfg, from, node_tip)?;
        self.in_sync.store(self.store.tip()? == Some(node_tip), Ordering::Relaxed);
        Ok(())
    }

    fn catch_up(&self, cfg: &RpcConfig, from: u32, to: u32) -> Result<(), String> {
        let count = to - from + 1;
        let workers = if count > 50 { FETCH_WORKERS } else { 1 };
        let mut blocks = Fetcher::start(cfg, from, to, workers, |rpc, h| {
            IndexBlock::from_json(&rpc.get_block(&rpc.get_block_hash(h)?, 2)?)
        });

        let mut prev_hash: Option<String> = if from == 0 {
            None
        } else {
            self.store.block_info(from - 1)?.map(|(h, _)| h)
        };
        let mut w = self.store.begin_write()?;
        let mut in_txn = 0u32;
        let started = Instant::now();
        let mut last_log = Instant::now();
        let near_tip = |h: u32| h + UNDO_WINDOW > to;
        let mut result = Ok(());

        while let Some((height, r)) = blocks.next() {
            let block = match r {
                Ok(b) => b,
                Err(e) => {
                    result = Err(format!("fetch block {height}: {e}"));
                    break;
                }
            };
            if let Some(ph) = &prev_hash {
                if block.prev_hash.as_ref() != Some(ph) {
                    // Chain moved under us — stop; the next pass
                    // runs reorg detection from the committed tip.
                    result = Err(format!("chain changed at {height} during catch-up"));
                    break;
                }
            }
            if let Err(e) = self.store.apply_block(&w, &block, near_tip(height)) {
                result = Err(format!("apply block {height}: {e}"));
                break;
            }
            prev_hash = Some(block.hash);
            let next = height + 1;
            in_txn += 1;
            let batch = if near_tip(next) { 1 } else { CATCHUP_BATCH };
            if in_txn >= batch {
                if next.is_multiple_of(100) {
                    self.store.prune_undo(&w, to.saturating_sub(UNDO_WINDOW))?;
                }
                w.commit().map_err(|e| e.to_string())?;
                w = self.store.begin_write()?;
                in_txn = 0;
            }
            if last_log.elapsed() > Duration::from_secs(30) {
                let done = next - from;
                let rate = done as f64 / started.elapsed().as_secs_f64().max(0.001);
                let eta = (to - height) as f64 / rate.max(0.001);
                log::info!("[{}] addr-index: {height}/{to} ({rate:.0} blk/s, ETA {:.0} min)", self.label, eta / 60.0);
                last_log = Instant::now();
            }
        }
        // Abort outstanding fetchers before committing.
        blocks.finish();
        if in_txn > 0 {
            w.commit().map_err(|e| e.to_string())?;
        } else {
            w.abort().map_err(|e| e.to_string())?;
        }
        if count > 10 && result.is_ok() && !shutdown::stopping() {
            log::info!(
                "[{}] addr-index: indexed {count} blocks in {:.1}s",
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
        // In batches: after a restart the whole mempool is new.
        let mut fetched: HashMap<String, Value> = HashMap::new();
        for chunk in unknown.chunks(100) {
            let params: Vec<Vec<Value>> = chunk.iter().map(|t| vec![json!(t), json!(true)]).collect();
            // A tx gone from the mempool meanwhile answers an error: skip it.
            for (t, answer) in chunk.iter().zip(rpc.batch("getrawtransaction", &params)?) {
                if let Ok(v) = answer {
                    fetched.insert(t.clone(), v);
                }
            }
        }
        let mut mp = self.mempool.write().unwrap();
        mp.sync(&txids, &self.store, |t| fetched.remove(t));
        Ok(())
    }
}

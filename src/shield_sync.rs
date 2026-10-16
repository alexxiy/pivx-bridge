//! Shield indexer: one thread per network keeps the shield store at the
//! node's tip. ZMQ block notifications wake it at once; it also checks
//! every 10 s, so it works without ZMQ.
//!
//! Catch-up fetches blocks with several RPC workers and commits every
//! 1000 blocks, so a restart resumes where it stopped. Blocks are never
//! skipped: on any error the pass stops and the next one retries from the
//! committed cursor.
//!
//! Blocks are read raw (`getblock <hash> 0`), which costs the node far
//! less than their JSON; only the last `CACHE_WINDOW` blocks are read as
//! JSON, for the proxy's block cache. A raw block the scanner can't
//! check against its merkle root is read as JSON instead.
use std::sync::atomic::Ordering;
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::api::AppState;
use crate::block_cache;
use crate::fetch::Fetcher;
use crate::rpc::RpcClient;
use crate::scanner::{self, ShieldBlock};
use crate::shield_store::HASH_WINDOW;
use crate::shutdown;

/// Parallel block fetchers used when far behind. pivxd answers 4 RPC
/// calls at a time by default (`rpcthreads`) and queues 16: the two
/// indexers and the client requests together stay within that.
const FETCH_WORKERS: usize = 4;
/// Scanned blocks per commit during catch-up.
const COMMIT_EVERY: usize = 1_000;
/// Within this many blocks of the tip, every block is committed at once.
const TIP_DISTANCE: u32 = 10;
/// Blocks within this distance of the tip are put in the proxy caches.
const CACHE_WINDOW: u32 = 1_000;
const POLL_INTERVAL: Duration = Duration::from_secs(10);

#[derive(Clone)]
pub struct RpcConfig {
    pub url: String,
    pub user: String,
    pub pass: String,
}

impl RpcConfig {
    pub fn client(&self) -> RpcClient {
        RpcClient::new(&self.url, &self.user, &self.pass)
    }
}

/// Start the indexer thread. Send `()` on the returned channel to make it
/// look for new blocks now.
pub fn spawn(state: Arc<AppState>, rpc: RpcConfig) -> mpsc::Sender<()> {
    let (tx, rx) = mpsc::channel::<()>();
    shutdown::register_waker(tx.clone());
    let thread = std::thread::Builder::new()
        .name(format!("shield-{}", state.label))
        .spawn(move || {
            let client = rpc.client();
            while !shutdown::stopping() {
                if let Err(e) = sync(&state, &client, &rpc) {
                    log::warn!("[{}] shield index: {e} — will retry", state.label);
                }
                if shutdown::stopping() {
                    break;
                }
                match rx.recv_timeout(POLL_INTERVAL) {
                    Ok(()) => while rx.try_recv().is_ok() {},
                    Err(mpsc::RecvTimeoutError::Timeout) => {}
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        shutdown::sleep(POLL_INTERVAL);
                    }
                }
            }
        })
        .expect("spawn shield indexer");
    shutdown::register(thread);
    tx
}

/// Bring the store to the node's tip, rolling back first on a reorg.
fn sync(state: &AppState, rpc: &RpcClient, cfg: &RpcConfig) -> Result<(), String> {
    let tip = rpc.get_block_count()? as u32;
    state.chain_height.store(tip, Ordering::Relaxed);

    if node_behind(state, rpc, tip)? {
        return Ok(());
    }
    if let Some(fork) = find_fork(state, rpc, tip)? {
        log::info!("[{}] Reorg: rescanning from block {fork}", state.label);
        state.store.rollback_to(fork)?;
        state.block_cache.write().unwrap().invalidate_from(fork);
        state.hash_cache.write().unwrap().invalidate_from(fork);
    }

    let cursor = state.store.cursor();
    let from = cursor.height + 1;
    if from > tip {
        return Ok(());
    }
    index_range(state, cfg, from, tip, cursor.hash)
}

/// Whether the node is behind the scanned chain on the same chain (after
/// a `-reindex`, or a node still syncing): then wait for it instead of
/// taking its lower tip for a reorg. Beyond the kept hashes there's no
/// telling, and waiting is the safe side too.
fn node_behind(state: &AppState, rpc: &RpcClient, tip: u32) -> Result<bool, String> {
    let cursor = state.store.cursor();
    let behind = cursor.height > tip
        && !cursor.hash.is_empty()
        && match state.store.hash_at(tip)? {
            Some(ours) => ours == rpc.get_block_hash(tip)?,
            None => true,
        };
    if behind != state.node_behind.swap(behind, Ordering::Relaxed) {
        if behind {
            log::info!("[{}] The node is at block {tip}, behind the shield index (block {}): waiting for it", state.label, cursor.height);
        } else if tip >= cursor.height {
            log::info!("[{}] The node caught up with the shield index", state.label);
        }
        // Otherwise the node is on another branch: the reorg is logged.
    }
    Ok(behind)
}

/// Where the node's chain leaves the scanned one, if it does.
fn find_fork(state: &AppState, rpc: &RpcClient, tip: u32) -> Result<Option<u32>, String> {
    let cursor = state.store.cursor();
    // Unknown hash: fresh store, or just imported from an old install.
    if cursor.hash.is_empty() || cursor.height == 0 {
        return Ok(None);
    }
    if cursor.height <= tip && rpc.get_block_hash(cursor.height)? == cursor.hash {
        return Ok(None);
    }
    let lowest = cursor.height.saturating_sub(HASH_WINDOW);
    let mut h = cursor.height - 1;
    while h > lowest {
        let Some(stored) = state.store.hash_at(h)? else {
            // Older than what we kept: rescan a safe margin.
            return Ok(Some(h.saturating_sub(100).max(1)));
        };
        if h <= tip && rpc.get_block_hash(h)? == stored {
            return Ok(Some(h + 1));
        }
        h -= 1;
    }
    log::warn!(
        "[{}] No common block in the last {HASH_WINDOW} blocks; rescanning from {}",
        state.label,
        lowest.max(1)
    );
    Ok(Some(lowest.max(1)))
}

/// One block as the shield index takes it.
struct Scanned {
    hash: String,
    prev_hash: Option<String>,
    shield: Option<ShieldBlock>,
    /// Near the tip: the block's JSON for the proxy's block cache.
    cache: Option<block_cache::Entry>,
    /// Why a block asked for raw was read as JSON.
    as_json: Option<String>,
}

impl Scanned {
    fn from_json(block: &Value, for_cache: bool) -> Result<Self, String> {
        Ok(Self {
            hash: block["hash"].as_str().unwrap_or_default().to_string(),
            prev_hash: block["previousblockhash"].as_str().map(str::to_string),
            shield: scanner::scan_block_json(block).map_err(|e| e.to_string())?,
            cache: if for_cache { block_cache::Entry::new(block) } else { None },
            as_json: None,
        })
    }
}

/// Fetches and scans block `h`, in a fetch worker. Blocks within
/// CACHE_WINDOW of `tip` are read as JSON, the others raw.
fn read_block(rpc: &RpcClient, h: u32, tip: u32) -> Result<Scanned, String> {
    let hash = rpc.get_block_hash(h)?;
    if h + CACHE_WINDOW > tip {
        return Scanned::from_json(&rpc.get_block(&hash, 2)?, true);
    }
    let answer = rpc.get_block(&hash, 0)?;
    let raw = answer.as_str().and_then(crate::hex::hex_decode).ok_or("getblock: not hex")?;
    let why = match scanner::scan_raw_block(h, &raw) {
        Ok(b) if b.hash == hash => {
            return Ok(Scanned { hash: b.hash, prev_hash: Some(b.prev_hash), shield: b.shield, cache: None, as_json: None });
        }
        Ok(b) => format!("its raw bytes hash to {}", b.hash),
        Err(e) => e,
    };
    let mut scanned = Scanned::from_json(&rpc.get_block(&hash, 2)?, false)?;
    scanned.as_json = Some(why);
    Ok(scanned)
}

fn index_range(state: &AppState, cfg: &RpcConfig, from: u32, tip: u32, cursor_hash: String) -> Result<(), String> {
    let count = tip - from + 1;
    let catching_up = count > 50;
    if catching_up {
        log::info!("[{}] Shield index: scanning blocks {from}..{tip} ({count} blocks)", state.label);
    }

    let workers = if catching_up { FETCH_WORKERS } else { 1 };
    let mut blocks = Fetcher::start(cfg, from, tip, workers, move |rpc, h| read_block(rpc, h, tip));

    let mut prev_hash = (!cursor_hash.is_empty()).then_some(cursor_hash);
    let mut shield: Vec<ShieldBlock> = Vec::new();
    let mut scanned: Vec<(u32, String)> = Vec::new();
    let mut found = 0usize;
    let mut as_json = 0usize;
    let started = Instant::now();
    let mut last_log = Instant::now();
    let mut result = Ok(());

    let commit = |shield: &mut Vec<ShieldBlock>, scanned: &mut Vec<(u32, String)>| -> Result<(), String> {
        state.store.append(shield, scanned)?;
        shield.clear();
        scanned.clear();
        Ok(())
    };

    while let Some((height, r)) = blocks.next() {
        let block = match r {
            Ok(b) => b,
            Err(e) => {
                result = Err(format!("block {height}: {e}"));
                break;
            }
        };
        if let Some(prev) = &prev_hash {
            if block.prev_hash.as_ref() != Some(prev) {
                // The chain moved under us; the next pass checks for a reorg.
                result = Err(format!("chain changed at block {height}"));
                break;
            }
        }
        if let Some(why) = &block.as_json {
            as_json += 1;
            if as_json == 1 {
                log::info!("[{}] Block {height} read as JSON: {why}", state.label);
            }
        }
        if let Some(b) = block.shield {
            if !catching_up {
                log::info!("[{}] Indexed shield block {height} ({} tx)", state.label, b.txs.len());
            }
            found += 1;
            shield.push(b);
        }
        if let Some(entry) = block.cache {
            state.block_cache.write().unwrap().insert_entry(&block.hash, 2, entry);
            state.hash_cache.write().unwrap().insert(height, block.hash.clone());
        }
        scanned.push((height, block.hash.clone()));
        prev_hash = Some(block.hash);

        if scanned.len() >= COMMIT_EVERY || height + 1 + TIP_DISTANCE > tip {
            if let Err(e) = commit(&mut shield, &mut scanned) {
                result = Err(format!("saving blocks: {e}"));
                break;
            }
        }
        if last_log.elapsed() > Duration::from_secs(30) {
            let done = height + 1 - from;
            let rate = done as f64 / started.elapsed().as_secs_f64().max(0.001);
            let eta = (tip - height) as f64 / rate.max(0.001);
            log::info!(
                "[{}] Shield index: {height}/{tip} ({rate:.0} blk/s, ETA {:.0} min, {found} shield blocks found)",
                state.label,
                eta / 60.0
            );
            last_log = Instant::now();
        }
    }
    blocks.finish();
    // Keep what was scanned before an error: those blocks are complete.
    if !scanned.is_empty() {
        if let Err(e) = commit(&mut shield, &mut scanned) {
            result = result.and(Err(format!("saving blocks: {e}")));
        }
    }
    if as_json > 1 {
        log::info!("[{}] {as_json} blocks read as JSON", state.label);
    }
    if catching_up && result.is_ok() && !shutdown::stopping() {
        log::info!(
            "[{}] Shield index: scanned {count} blocks in {:.0} s ({found} shield blocks, {} in total)",
            state.label,
            started.elapsed().as_secs_f64(),
            state.store.block_count().unwrap_or(0)
        );
    }
    result
}

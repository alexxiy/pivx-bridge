//! Shield indexer: one thread per network keeps the shield store at the
//! node's tip. ZMQ block notifications wake it at once; it also checks
//! every 10 s, so it works without ZMQ.
//!
//! Catch-up fetches blocks with several RPC workers and commits every
//! 1000 blocks, so a restart resumes where it stopped. Blocks are never
//! skipped: on any error the pass stops and the next one retries from the
//! committed cursor.
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{mpsc, Arc};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::api::AppState;
use crate::rpc::RpcClient;
use crate::scanner::{self, ShieldBlock};
use crate::shield_store::HASH_WINDOW;
use crate::shutdown;

/// Parallel block fetchers used when far behind. pivxd answers 4 RPC
/// calls at a time by default (`rpcthreads`) and queues 16: the two
/// indexers and the client requests together stay within that.
const FETCH_WORKERS: usize = 4;
/// How far the fetchers may get ahead of the block being stored. Fetched
/// blocks wait in memory for the ones before them: without a limit, one
/// slow fetch would let the others fill memory with blocks.
const LOOKAHEAD: u32 = 1_000;
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
        } else {
            log::info!("[{}] The node caught up with the shield index", state.label);
        }
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

fn index_range(state: &AppState, cfg: &RpcConfig, from: u32, tip: u32, cursor_hash: String) -> Result<(), String> {
    let count = tip - from + 1;
    let catching_up = count > 50;
    if catching_up {
        log::info!("[{}] Shield index: scanning blocks {from}..{tip} ({count} blocks)", state.label);
    }

    let workers = if catching_up { FETCH_WORKERS } else { 1 };
    let next = Arc::new(AtomicU32::new(from));
    // The block being stored; fetchers stay within LOOKAHEAD of it.
    let stored = Arc::new(AtomicU32::new(from));
    let stop = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::sync_channel::<(u32, Result<Value, String>)>(256);
    let mut handles = Vec::new();
    for _ in 0..workers {
        let (next, stored, stop, tx, cfg) = (next.clone(), stored.clone(), stop.clone(), tx.clone(), cfg.clone());
        handles.push(std::thread::spawn(move || {
            let rpc = cfg.client();
            let stopped = || stop.load(Ordering::SeqCst) || shutdown::stopping();
            while !stopped() {
                let h = next.fetch_add(1, Ordering::SeqCst);
                if h > tip {
                    break;
                }
                while h > stored.load(Ordering::SeqCst) + LOOKAHEAD && !stopped() {
                    std::thread::sleep(Duration::from_millis(20));
                }
                let mut res = Err(String::new());
                for attempt in 0..3 {
                    res = rpc.get_block_hash(h).and_then(|hash| rpc.get_block(&hash, 2));
                    if res.is_ok() || stopped() {
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

    let mut prev_hash = (!cursor_hash.is_empty()).then_some(cursor_hash);
    let mut pending: BTreeMap<u32, Result<Value, String>> = BTreeMap::new();
    let mut expect = from;
    let mut shield: Vec<ShieldBlock> = Vec::new();
    let mut scanned: Vec<(u32, String)> = Vec::new();
    let mut found = 0usize;
    let started = Instant::now();
    let mut last_log = Instant::now();
    let mut result = Ok(());

    let commit = |shield: &mut Vec<ShieldBlock>, scanned: &mut Vec<(u32, String)>| -> Result<(), String> {
        state.store.append(shield, scanned)?;
        shield.clear();
        scanned.clear();
        Ok(())
    };

    'outer: for (h, r) in rx.iter() {
        if shutdown::stopping() {
            break;
        }
        pending.insert(h, r);
        while let Some(r) = pending.remove(&expect) {
            let block = match r {
                Ok(b) => b,
                Err(e) => {
                    result = Err(format!("block {expect}: {e}"));
                    break 'outer;
                }
            };
            let hash = block["hash"].as_str().unwrap_or_default().to_string();
            if let Some(prev) = &prev_hash {
                if block["previousblockhash"].as_str() != Some(prev.as_str()) {
                    // The chain moved under us; the next pass checks for a reorg.
                    result = Err(format!("chain changed at block {expect}"));
                    break 'outer;
                }
            }
            match scanner::scan_block_json(&block) {
                Ok(Some(b)) => {
                    if !catching_up {
                        log::info!("[{}] Indexed shield block {expect} ({} tx)", state.label, b.txs.len());
                    }
                    found += 1;
                    shield.push(b);
                }
                Ok(None) => {}
                Err(e) => {
                    result = Err(e.to_string());
                    break 'outer;
                }
            }
            if expect + CACHE_WINDOW > tip {
                state.block_cache.write().unwrap().insert(&hash, 2, &block);
                state.hash_cache.write().unwrap().insert(expect, hash.clone());
            }
            scanned.push((expect, hash.clone()));
            prev_hash = Some(hash);
            expect += 1;
            stored.store(expect, Ordering::SeqCst);

            if scanned.len() >= COMMIT_EVERY || expect + TIP_DISTANCE > tip {
                if let Err(e) = commit(&mut shield, &mut scanned) {
                    result = Err(format!("saving blocks: {e}"));
                    break 'outer;
                }
            }
            if last_log.elapsed() > Duration::from_secs(30) {
                let done = expect - from;
                let rate = done as f64 / started.elapsed().as_secs_f64().max(0.001);
                let eta = (tip + 1 - expect) as f64 / rate.max(0.001);
                log::info!(
                    "[{}] Shield index: {}/{tip} ({rate:.0} blk/s, ETA {:.0} min, {found} shield blocks found)",
                    state.label,
                    expect - 1,
                    eta / 60.0
                );
                last_log = Instant::now();
            }
        }
    }
    stop.store(true, Ordering::SeqCst);
    drop(rx);
    // Keep what was scanned before an error: those blocks are complete.
    if !scanned.is_empty() {
        if let Err(e) = commit(&mut shield, &mut scanned) {
            result = result.and(Err(format!("saving blocks: {e}")));
        }
    }
    // When stopping, a fetcher may still wait on the node: don't wait
    // for it, what was scanned is saved.
    if !shutdown::stopping() {
        for h in handles {
            let _ = h.join();
        }
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

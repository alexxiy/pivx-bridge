/// PIVX Bridge — drop-in replacement for PivxNodeController.
///
/// Connects to a PIVX full node, scans for Sapling transactions, and serves
/// shield data to light wallets (MyPIVXWallet) over HTTP.
mod addr_index;
mod api;
mod block_cache;
mod cache;
mod config;
mod hex;
mod index;
mod proxy;
mod rpc;
mod scanner;
mod stream;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use tokio::sync::{Mutex, RwLock};
use tower_http::compression::{CompressionLayer, CompressionLevel};
use tower_http::cors::CorsLayer;

/// Network initialization parameters.
struct NetworkConfig<'a> {
    label: &'a str,
    rpc_url: &'a str,
    rpc_user: &'a str,
    rpc_pass: &'a str,
    index_path: &'a str,
    cache_path: &'a str,
    /// Sidecar file persisting `last_scanned_height` + the hash of
    /// that block. Lives next to the index/bin so an atomic save
    /// pass updates all three together.
    cursor_path: &'a str,
    sapling_height: u32,
    allowed_rpcs: Vec<String>,
}

/// Initialize a network: connect to node, scan blocks, build state.
fn init_network(cfg: &NetworkConfig) -> Option<Arc<api::AppState>> {
    let label = cfg.label;
    eprintln!("\n  [{label}] Connecting to {}...", cfg.rpc_url);

    let rpc = rpc::RpcClient::new(cfg.rpc_url, cfg.rpc_user, cfg.rpc_pass);

    let chain_height = match rpc.get_block_count() {
        Ok(h) => {
            eprintln!("  [{label}] Connected — chain height: {h}");
            h as u32
        }
        Err(e) => {
            eprintln!("  [{label}] Cannot connect: {e}");
            return None;
        }
    };

    let mut shield_index = index::load_or_create(cfg.index_path);

    if let Some(last_good) = cache::recover_cache(cfg.cache_path) {
        eprintln!("  [{label}] Cache recovered — last complete block: {last_good}");
    }

    let mut cache_file = cache::open_cache(cfg.cache_path)
        .expect("failed to open cache file");

    // Resume from the persisted scan cursor when present. Falls back
    // to `index.last_height() + 1` only on first run / cursor missing.
    // Without this, the bridge re-scans every non-shield block between
    // the last shield block and the crash, which is wasteful and (per
    // earlier audit) is one of the latent corruption surfaces — a
    // crash between disk write and index save would otherwise produce
    // duplicate appends.
    let mut scan_cursor = index::ScanCursor::load(cfg.cursor_path).unwrap_or_default();

    // Block cache — 1000 blocks covers the tip range where most traffic is
    let block_cache = std::sync::RwLock::new(block_cache::BlockCache::new(1000));

    // Reorg-across-restart check: the in-memory block cache starts
    // empty after every restart, so the live reorg detector would
    // miss any reorg that landed while the bridge was down. Compare
    // the persisted `last_scanned_hash` against PIVX core's current
    // hash for that height; if they diverge, walk back to find the
    // fork and truncate state before the forward scan resumes.
    if !scan_cursor.last_scanned_hash.is_empty() && scan_cursor.last_scanned_height > 0 {
        if let Ok(current_hash) = rpc.get_block_hash(scan_cursor.last_scanned_height) {
            if current_hash != scan_cursor.last_scanned_hash {
                eprintln!(
                    "  [{label}] Reorg-across-restart detected at height {} (was {}, now {}) — rolling state back",
                    scan_cursor.last_scanned_height,
                    &scan_cursor.last_scanned_hash[..16.min(scan_cursor.last_scanned_hash.len())],
                    &current_hash[..16.min(current_hash.len())],
                );
                // Walk backwards via RPC to find the actual fork
                // point. This is one-shot startup work; we don't
                // care about the 100-block soft cap from
                // find_fork_point.
                let fork_height = find_fork_point_via_rpc(
                    &rpc,
                    scan_cursor.last_scanned_height,
                    &shield_index,
                );
                eprintln!("  [{label}] Fork at height {fork_height}");
                // Truncate shield.bin + index to before the fork
                if let Some(offset) = shield_index.offset_for_height(fork_height) {
                    if let Err(e) = cache::truncate_to(&mut cache_file, offset) {
                        eprintln!("  [{label}] WARN: cache truncate failed: {e}");
                    }
                }
                shield_index.remove_from(fork_height);
                if let Err(e) = shield_index.save(cfg.index_path) {
                    eprintln!("  [{label}] WARN: index save failed: {e}");
                }
                scan_cursor.last_scanned_height = fork_height.saturating_sub(1);
                scan_cursor.last_scanned_hash.clear();
                let _ = scan_cursor.save(cfg.cursor_path);
            }
        }
    }
    // After potential rollback, recompute scan_from
    let scan_from = if scan_cursor.last_scanned_height >= cfg.sapling_height {
        scan_cursor.last_scanned_height + 1
    } else {
        shield_index
            .last_height()
            .map(|h| h + 1)
            .unwrap_or(cfg.sapling_height)
    };

    if scan_from <= chain_height {
        eprintln!("  [{label}] Scanning blocks {scan_from}..{chain_height}...");

        match scanner::scan_range(&rpc, scan_from, chain_height, &block_cache, chain_height, |done, total| {
            if total > 0 && (done % 100 == 0 || done == total) {
                eprint!("\r  [{label}] Progress: {done}/{total} blocks");
            }
        }) {
            Ok(blocks) => {
                let count = blocks.len();
                // CRITICAL: only update the index if the cache write
                // succeeded. The previous code path called
                // `shield_index.add(block.height, 0)` on cache failure
                // which poisoned the index with offset=0 (=== position
                // of the first-ever block) — every subsequent
                // streaming request for that height would return the
                // entire shield.bin from the start. On disk write
                // failure: log loudly and bail; the next pass will
                // retry the same range.
                match cache::append_blocks(&mut cache_file, &blocks) {
                    Ok(entries) => {
                        for (height, offset, _len) in entries {
                            shield_index.add(height, offset);
                        }
                        if let Err(e) = shield_index.save(cfg.index_path) {
                            eprintln!("\n  [{label}] Warning: index save failed: {e}");
                        }
                    }
                    Err(e) => {
                        eprintln!("\n  [{label}] Cache write failed: {e} — will retry on next pass");
                    }
                }
                eprintln!("\n  [{label}] Found {count} shield blocks ({} total)",
                    shield_index.shield_heights.len());
            }
            Err(e) => {
                eprintln!("\n  [{label}] Scan error: {e}");
            }
        }
    } else {
        eprintln!("  [{label}] Up to date — {} shield blocks",
            shield_index.shield_heights.len());
    }

    // Update cursor with the final post-scan state
    scan_cursor.last_scanned_height = chain_height;
    if let Ok(h) = rpc.get_block_hash(chain_height) {
        scan_cursor.last_scanned_hash = h;
    }
    let _ = scan_cursor.save(cfg.cursor_path);

    // Load shield.bin into memory for zero-disk-I/O serving. Fail
    // loudly on read errors — silently treating an unreadable cache
    // as empty would let the bridge run with a buffer that doesn't
    // match the index, and clients would receive empty responses for
    // requests that should have returned data.
    let shield_buffer = match std::fs::read(cfg.cache_path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => panic!("failed to read shield buffer at {}: {e}", cfg.cache_path),
    };
    let buffer_mb = shield_buffer.len() as f64 / (1024.0 * 1024.0);
    eprintln!("  [{label}] Shield buffer loaded: {buffer_mb:.1} MB in memory");

    Some(Arc::new(api::AppState {
        rpc: rpc::RpcClient::new(cfg.rpc_url, cfg.rpc_user, cfg.rpc_pass),
        index: RwLock::new(shield_index),
        cache_file: Mutex::new(cache_file),
        shield_buffer: RwLock::new(shield_buffer),
        allowed_rpcs: cfg.allowed_rpcs.clone(),
        last_scanned_height: RwLock::new(scan_cursor.last_scanned_height),
        last_scanned_hash: RwLock::new(scan_cursor.last_scanned_hash.clone()),
        hash_cache: RwLock::new(api::HashCache::new(1000)),
        block_cache,
        chain_height: AtomicU32::new(chain_height),
        zmq_active: std::sync::atomic::AtomicBool::new(false),
        indexing: std::sync::atomic::AtomicBool::new(false),
        cursor_path: cfg.cursor_path.to_string(),
    }))
}

/// Walk backwards from `height` to find the fork point using RPC.
/// Used at startup when the in-memory block_cache is empty. Cheap
/// — only fires when a reorg-across-restart is actually detected,
/// and walks at most as far as the chain has reorged (typically 1-2
/// blocks). Returns the first height that's still on both chains
/// (fork_height = first block that diverged).
fn find_fork_point_via_rpc(
    rpc: &rpc::RpcClient,
    last_scanned: u32,
    index: &index::ShieldIndex,
) -> u32 {
    // We know the hash AT last_scanned diverges from what we stored.
    // Walk backwards block-by-block until we find one whose
    // current-chain hash matches an earlier-known hash. Without
    // historical hashes the only known reference points are the
    // shield index entries that didn't move (the byte offset is
    // ours, but the block hash is the chain's). Conservative
    // fallback: walk back one block at a time and trust whatever
    // RPC returns — at worst we re-index a few extra blocks, which
    // is cheap and correct.
    //
    // The index entries don't store block hashes (yet), so we can't
    // do exact-match disambiguation here. Roll back to the last
    // *indexed* shield block before `last_scanned` and let the
    // forward scan re-do everything between there and tip. That's a
    // few hundred blocks of re-scan in the worst case (one shield
    // block per ~100 ordinary blocks at current activity levels);
    // strictly correct, doesn't require hashes-per-entry.
    let last_shield = index
        .shield_heights
        .iter()
        .rev()
        .find(|&&h| h < last_scanned)
        .copied()
        .unwrap_or(0);
    // The fork is somewhere between last_shield and last_scanned.
    // Returning last_shield + 1 means "discard the index entry at
    // last_shield's position?" No — last_shield itself is fine
    // (we found it under last_scanned, before the divergence).
    // Re-scan from last_shield + 1 forward.
    let _ = rpc; // RPC not needed for this conservative variant
    last_shield + 1
}

/// Directory with the Sapling proving parameters, if available.
fn sapling_params_dir(config: &config::Config) -> Option<std::path::PathBuf> {
    let dir = config
        .sapling_params_dir
        .clone()
        .map(std::path::PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| std::path::PathBuf::from(h).join(".pivx-params")))?;
    let ok = ["sapling-output.params", "sapling-spend.params"]
        .iter()
        .all(|f| dir.join(f).is_file());
    ok.then_some(dir)
}

/// `/sapling-output.params` + `/sapling-spend.params`, so light wallets
/// can fetch the proving parameters from the same server.
fn sapling_params_routes(dir: &std::path::Path) -> Router {
    use axum::http::{header::CONTENT_ENCODING, HeaderValue};
    use tower_http::services::ServeFile;
    use tower_http::set_header::SetResponseHeaderLayer;
    Router::new()
        .route_service("/sapling-output.params", ServeFile::new(dir.join("sapling-output.params")))
        .route_service("/sapling-spend.params", ServeFile::new(dir.join("sapling-spend.params")))
        // Random-looking 50 MB files: tell the gzip layer to leave them alone.
        .layer(SetResponseHeaderLayer::if_not_present(
            CONTENT_ENCODING,
            HeaderValue::from_static("identity"),
        ))
}

/// Build the standard route set for a network.
fn build_routes(state: Arc<api::AppState>) -> Router {
    Router::new()
        .route("/getshielddata", get(api::get_shield_data))
        .route("/getshielddatalength", get(api::get_shield_data_length))
        .route("/getblockcount", get(api::get_block_count))
        .route("/getshieldblocks", get(api::get_shield_blocks))
        .route("/sendrawtransaction", post(api::send_raw_transaction))
        .route("/address_index", get(api::get_address_index))
        .route("/{method}", get(proxy::rpc_proxy))
        .with_state(state)
}

/// Scan for new blocks and index them. Shared by both ZMQ and polling.
///
/// Detects chain reorganizations by verifying the parent hash chain.
/// On reorg, walks back to the fork point and invalidates cached blocks.
fn index_new_blocks(
    label: &'static str,
    rpc_url: &str,
    rpc_user: &str,
    rpc_pass: &str,
    state: &Arc<api::AppState>,
    index_path: &str,
    source: &str,
) {
    // Mutual-exclusion gate: ZMQ and poll can both fire at the same tip,
    // and the filter-then-append critical section below is not atomic —
    // the shield_heights check and the shield.bin/buffer append happen as
    // separate awaits. Without this gate, two concurrent entries both pass
    // the filter (because neither has committed its append yet) and both
    // write the block, producing the duplicate-block-in-stream that
    // PIVX-Labs/pivx-bridge#1 reports. If someone else is already indexing,
    // just return — the winner will cover whatever we would have done.
    if state.indexing.compare_exchange(
        false,
        true,
        Ordering::SeqCst,
        Ordering::SeqCst,
    ).is_err() {
        return;
    }
    // RAII guard so the flag is released on every exit path.
    struct IndexingGuard<'a>(&'a std::sync::atomic::AtomicBool);
    impl Drop for IndexingGuard<'_> {
        fn drop(&mut self) {
            self.0.store(false, Ordering::SeqCst);
        }
    }
    let _guard = IndexingGuard(&state.indexing);

    let rpc = rpc::RpcClient::new(rpc_url, rpc_user, rpc_pass);

    let chain_height = match rpc.get_block_count() {
        Ok(h) => h as u32,
        Err(e) => {
            eprintln!("  [{label}] {source} RPC error: {e}");
            return;
        }
    };

    // Update global chain height (used for rehydration)
    state.chain_height.store(chain_height, Ordering::Relaxed);

    let rt = tokio::runtime::Handle::current();
    let last_scanned = rt.block_on(async { *state.last_scanned_height.read().await });

    let scan_from = last_scanned + 1;
    if scan_from > chain_height {
        return;
    }

    // --- Reorg detection ---
    if let Ok(new_hash) = rpc.get_block_hash(scan_from) {
        if let Ok(new_block) = rpc.get_block(&new_hash, 1) {
            if let Some(prev_hash) = new_block.get("previousblockhash").and_then(|v| v.as_str()) {
                let reorged = state.block_cache.read().unwrap().detect_reorg(scan_from, prev_hash);
                if reorged {
                    let fork_height = find_fork_point(&rpc, &state.block_cache, scan_from);
                    eprintln!("  [{label}] {source}: reorg detected! Fork at height {fork_height}");
                    state.block_cache.write().unwrap().invalidate_from(fork_height);

                    // Atomic shield-state truncation. Holds index +
                    // buffer + file locks together so a concurrent
                    // streaming reader can never observe torn state
                    // (index says here / buffer holds different
                    // bytes). Truncate ORDER MATTERS: compute
                    // offset BEFORE removing entries, since once
                    // they're gone we lose the offset.
                    rt.block_on(async {
                        let mut index = state.index.write().await;
                        let mut buffer = state.shield_buffer.write().await;
                        let mut file = state.cache_file.lock().await;

                        let truncate_offset = match index.offset_for_height(fork_height) {
                            Some(o) => o as usize,
                            None => {
                                // No indexed shield block at-or-after
                                // fork_height — nothing on the shield
                                // side to truncate. Cursor still
                                // needs to rewind.
                                *state.last_scanned_height.write().await = fork_height.saturating_sub(1);
                                return;
                            }
                        };

                        if let Err(e) = cache::truncate_to(&mut file, truncate_offset as u64) {
                            eprintln!("  [{label}] WARN: cache truncate failed: {e}");
                            // Don't proceed with the index/buffer
                            // trim — we'd diverge from disk. Bail.
                            return;
                        }
                        buffer.truncate(truncate_offset);
                        index.remove_from(fork_height);
                        if let Err(e) = index.save(index_path) {
                            eprintln!("  [{label}] WARN: index save failed: {e}");
                        }

                        *state.last_scanned_height.write().await = fork_height.saturating_sub(1);
                        // Wipe the persisted hash too — the next
                        // append will re-populate it. Without this,
                        // a crash between truncate and the next
                        // successful append would leave a cursor
                        // pointing at a hash that no longer exists.
                        state.last_scanned_hash.write().await.clear();
                        let cursor = index::ScanCursor {
                            last_scanned_height: fork_height.saturating_sub(1),
                            last_scanned_hash: String::new(),
                        };
                        let _ = cursor.save(&state.cursor_path);
                    });
                }
            }
        }
    }

    // Re-read last_scanned (may have changed from reorg handling)
    let last_scanned = rt.block_on(async { *state.last_scanned_height.read().await });
    let scan_from = last_scanned + 1;
    if scan_from > chain_height {
        return;
    }

    // One-block-at-a-time indexer loop. Invariant: `last_scanned_height`
    // ONLY advances after scan_block returns Ok for block `last_scanned + 1`.
    // On Err we break and return — the next poll tick (or ZMQ event) will
    // re-enter and retry the exact same block. No skipping, no advancing
    // past a block we couldn't process. See feedback_indexer_never_skip.md
    // for the incident on the Kerrigan bridge that motivated this fix; the
    // same bug pattern existed here and is fixed in parallel.
    let mut indexed_count: u32 = 0;
    let mut needs_persist = false;
    loop {
        let target_h = {
            let cursor = rt.block_on(async { *state.last_scanned_height.read().await });
            cursor + 1
        };
        if target_h > chain_height {
            break;
        }

        match scanner::scan_block(&rpc, target_h, &state.block_cache, chain_height) {
            Ok(Some(block)) => {
                let appended = rt.block_on(async {
                    // Idempotency belt-and-suspenders: if this height is
                    // already indexed (rare — ZMQ+poll overlap), skip
                    // the append but still advance past it.
                    {
                        let idx = state.index.read().await;
                        if idx.shield_heights.contains(&block.height) {
                            return true;
                        }
                    }

                    let block_slice = std::slice::from_ref(&block);
                    let new_bytes = stream::encode_shield_stream(
                        block_slice,
                        api::StreamFormat::PivxCompat,
                    );

                    let cache_entries = {
                        let mut file = state.cache_file.lock().await;
                        cache::append_blocks(&mut file, block_slice).ok()
                    };

                    {
                        let mut buffer = state.shield_buffer.write().await;
                        buffer.extend_from_slice(&new_bytes);
                    }

                    let mut index = state.index.write().await;
                    if let Some(entries) = cache_entries {
                        for (height, offset, _len) in entries {
                            index.add(height, offset);
                        }
                        if let Err(e) = index.save(index_path) {
                            eprintln!("  [{label}] Index save failed: {e}");
                        }
                        true
                    } else {
                        // Cache write failed — do NOT poison the
                        // index with offset=0. Pre-fix this branch
                        // called `index.add(block.height, 0)` which
                        // caused every subsequent streaming request
                        // for that height to return shield.bin from
                        // the start (offset 0 = the first-ever
                        // block). Better to log + bail; the next
                        // pass retries the same block.
                        eprintln!(
                            "  [{label}] {source}: block {target_h} cache write failed, NOT poisoning index — will retry",
                        );
                        false
                    }
                });
                if !appended {
                    eprintln!("  [{label}] {source}: block {target_h} append failed, will retry");
                    break;
                }

                // Advance cursor — the only place it moves after a
                // shield block. Persist the cursor (with the new
                // hash) so a crash here doesn't lose progress, and
                // a reorg-across-restart at this exact height can
                // be detected on next startup.
                let target_hash = rpc.get_block_hash(target_h).ok();
                rt.block_on(async {
                    *state.last_scanned_height.write().await = target_h;
                    if let Some(h) = target_hash.as_ref() {
                        *state.last_scanned_hash.write().await = h.clone();
                    }
                    let cursor = index::ScanCursor {
                        last_scanned_height: target_h,
                        last_scanned_hash: target_hash.clone().unwrap_or_default(),
                    };
                    let _ = cursor.save(&state.cursor_path);
                });
                needs_persist = false;
                indexed_count += 1;
                eprintln!("  [{label}] {source}: indexed shield block {target_h} (chain: {chain_height})");
            }
            Ok(None) => {
                // No shield data in this block — successful scan,
                // advance cursor in memory. We only persist the
                // cursor at loop exit to avoid a disk write per
                // empty block during catch-up.
                rt.block_on(async {
                    *state.last_scanned_height.write().await = target_h;
                });
                needs_persist = true;
            }
            Err(e) => {
                // Transient (or persistent) scan failure. Do NOT advance —
                // next tick will retry this exact height.
                eprintln!("  [{label}] {source}: block {target_h} scan failed: {e} — will retry");
                break;
            }
        }
    }

    if needs_persist {
        // Persist whatever the final cursor state is. We grab the
        // hash for the new cursor height too so reorg-across-
        // restart detection works after a crash here.
        let final_h = rt.block_on(async { *state.last_scanned_height.read().await });
        let final_hash = rpc.get_block_hash(final_h).unwrap_or_default();
        rt.block_on(async {
            let index = state.index.read().await;
            if let Err(e) = index.save(index_path) {
                eprintln!("  [{label}] Index save failed: {e}");
            }
            *state.last_scanned_hash.write().await = final_hash.clone();
            let cursor = index::ScanCursor {
                last_scanned_height: final_h,
                last_scanned_hash: final_hash,
            };
            let _ = cursor.save(&state.cursor_path);
        });
    }

    if indexed_count > 0 {
        eprintln!("  [{label}] {source}: catch-up complete ({indexed_count} shield block(s) this pass)");
    }
}

/// Walk backwards from `height` to find where the chain diverges
/// from our cache. Returns the lowest height that's still in disagreement
/// — i.e. the first block on the new (canonical) chain that needs to
/// be re-indexed.
///
/// Strategy:
///   1. Walk backwards block-by-block.
///   2. If the height is in the in-memory `block_cache`, compare its
///      cached hash against the RPC's current hash. Match → that block
///      is on both chains, the fork is at `h + 1`. Mismatch → keep
///      walking back.
///   3. If the height is NOT in the cache (cold start, or cache evicted
///      via LRU), fall back to walking the RPC's previousblockhash
///      chain from `height` down. Without this fallback the previous
///      implementation returned `h + 1` on the first cache miss,
///      which on a cold cache (i.e. immediately after restart) means
///      "fork is at the new tip" — i.e. a no-op invalidate, silently
///      losing the reorg.
///
/// Bounded at 1000 blocks to avoid unbounded RPC traffic on a
/// pathological deep reorg; if 1000 isn't enough, the bridge logs
/// loudly and returns the bottom of the search window — the next
/// pass will re-scan from there forward, which is correct (just
/// expensive).
fn find_fork_point(
    rpc: &rpc::RpcClient,
    block_cache: &std::sync::RwLock<block_cache::BlockCache>,
    height: u32,
) -> u32 {
    const SEARCH_DEPTH: u32 = 1000;
    let limit = height.saturating_sub(SEARCH_DEPTH);
    let mut h = height.saturating_sub(1);

    // Phase 1: walk backwards using cache hits where available, RPC
    // for cache misses. Either way we compare against the chain's
    // current hash.
    while h > limit {
        // Bind the read guard so the borrow returned by
        // `hash_for_height` lives long enough; otherwise the temp
        // guard dies at the semicolon and the &str dangles.
        let cached_hash: Option<String> = {
            let guard = block_cache.read().unwrap();
            guard.hash_for_height(h).map(|s| s.to_string())
        };
        let candidate = match cached_hash {
            Some(c) => c,
            None => match rpc.get_block_hash(h) {
                Ok(node_hash) => {
                    // Cache miss + we got the chain's current hash.
                    // No previously-recorded hash to compare to,
                    // so we can't decide whether this height
                    // reorged or not — keep walking back.
                    let _ = node_hash;
                    h = h.saturating_sub(1);
                    continue;
                }
                Err(_) => {
                    // RPC error — bail conservatively. Returning
                    // `h + 1` from current `h` means the caller
                    // will re-scan from h+1 forward; that's at most
                    // SEARCH_DEPTH blocks of redundant work.
                    return h.saturating_add(1);
                }
            },
        };
        match rpc.get_block_hash(h) {
            Ok(node_hash) if node_hash == candidate => return h + 1,
            Ok(_) => { h = h.saturating_sub(1); }
            Err(_) => return h.saturating_add(1),
        }
    }

    // Reached the search window's lower bound without finding a
    // match. Log loudly — this only happens on >=SEARCH_DEPTH-block
    // reorgs, which are extremely rare on PIVX (and a strong signal
    // something is very wrong with the node).
    eprintln!(
        "  [find_fork_point] WARN: walked back {SEARCH_DEPTH} blocks from {height} without finding fork; returning {limit}",
    );
    limit + 1
}

/// Spawn ZMQ listener — instant block notifications when it works.
fn spawn_zmq_listener(
    label: &'static str,
    zmq_url: String,
    rpc_url: String,
    rpc_user: String,
    rpc_pass: String,
    state: Arc<api::AppState>,
    index_path: String,
) {
    tokio::spawn(async move {
        use futures::StreamExt;

        loop {
            eprintln!("  [{label}] ZMQ subscribing to {zmq_url}...");
            let mut subscriber = match bitcoincore_zmq::subscribe_async(&[&zmq_url]) {
                Ok(s) => {
                    eprintln!("  [{label}] ZMQ connected — polling disabled");
                    state.zmq_active.store(true, std::sync::atomic::Ordering::Relaxed);
                    s
                }
                Err(e) => {
                    state.zmq_active.store(false, std::sync::atomic::Ordering::Relaxed);
                    eprintln!("  [{label}] ZMQ failed: {e} — polling re-enabled, retrying in 30s");
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    continue;
                }
            };

            while let Some(msg) = subscriber.next().await {
                let msg = match msg {
                    Ok(m) => m,
                    Err(e) => {
                        state.zmq_active.store(false, std::sync::atomic::Ordering::Relaxed);
                        eprintln!("  [{label}] ZMQ error: {e} — polling re-enabled, reconnecting");
                        break;
                    }
                };
                if !matches!(msg, bitcoincore_zmq::Message::HashBlock(_, _)) {
                    continue;
                }
                let s = state.clone();
                let r = rpc_url.clone();
                let u = rpc_user.clone();
                let p = rpc_pass.clone();
                let i = index_path.clone();
                tokio::task::spawn_blocking(move || {
                    index_new_blocks(label, &r, &u, &p, &s, &i, "ZMQ");
                }).await.ok();
            }

            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });
}

/// Spawn polling loop — always runs, catches anything ZMQ misses.
/// Uses nextblockhash chaining instead of rescanning entire ranges.
fn spawn_poller(
    label: &'static str,
    rpc_url: String,
    rpc_user: String,
    rpc_pass: String,
    state: Arc<api::AppState>,
    index_path: String,
) {
    tokio::spawn(async move {
        eprintln!("  [{label}] Polling standby (10s interval, active when ZMQ is down)");
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;

            // Skip polling entirely when ZMQ is connected
            if state.zmq_active.load(std::sync::atomic::Ordering::Relaxed) {
                continue;
            }

            let last_scanned = *state.last_scanned_height.read().await;

            let s = state.clone();
            let r = rpc_url.clone();
            let u = rpc_user.clone();
            let p = rpc_pass.clone();
            let i = index_path.clone();
            tokio::task::spawn_blocking(move || {
                poll_new_blocks(label, &r, &u, &p, &s, &i, last_scanned);
            }).await.ok();
        }
    });
}

/// Poll for new blocks by chaining via nextblockhash from the last scanned block.
fn poll_new_blocks(
    label: &'static str,
    rpc_url: &str,
    rpc_user: &str,
    rpc_pass: &str,
    state: &Arc<api::AppState>,
    index_path: &str,
    last_scanned: u32,
) {
    let rpc = rpc::RpcClient::new(rpc_url, rpc_user, rpc_pass);

    // Get the last scanned block to check for nextblockhash
    let last_hash = match rpc.get_block_hash(last_scanned) {
        Ok(h) => h,
        Err(_) => return,
    };

    let block_json = match rpc.get_block(&last_hash, 1) {
        Ok(j) => j,
        Err(_) => return,
    };

    // No new block yet — nothing to do
    let next_hash = match block_json.get("nextblockhash").and_then(|v| v.as_str()) {
        Some(h) => h.to_string(),
        None => return,
    };

    // New block(s) exist — figure out range and scan
    let chain_height = match rpc.get_block_count() {
        Ok(h) => h as u32,
        Err(_) => return,
    };

    let scan_from = last_scanned + 1;
    if scan_from > chain_height {
        return;
    }

    // Cache the hashes we already know
    let rt = tokio::runtime::Handle::current();
    rt.block_on(async {
        let mut cache = state.hash_cache.write().await;
        cache.insert(last_scanned, last_hash);
        cache.insert(scan_from, next_hash);
    });

    index_new_blocks(label, rpc_url, rpc_user, rpc_pass, state, index_path, "Poll");

    // NOTE: Do NOT stomp `last_scanned_height` to `chain_height` here.
    // `index_new_blocks` is the only authority on the cursor — it
    // advances per-block on success and stops on the first error,
    // preserving the never-skip invariant. The earlier code path
    // unconditionally jumped the cursor to chain_height after the
    // call returned, which silently skipped any block that errored
    // mid-loop and left the index missing entries. See
    // feedback_indexer_never_skip.md.
    let _ = chain_height;
}

/// Open the address index, start its indexer thread and return its
/// `/api/v2/*` routes. Exits the process if the index can't be opened
/// (an operator who asked for it should notice).
fn start_addr_index(label: &'static str, path: &str, rpc_url: &str, rpc_user: &str, rpc_pass: &str) -> Router {
    let idx = addr_index::AddrIndex::open(label, path, rpc_url, rpc_user, rpc_pass)
        .unwrap_or_else(|e| panic!("[{label}] address index failed to open: {e}"));
    idx.spawn(rpc_url.to_string(), rpc_user.to_string(), rpc_pass.to_string());
    eprintln!("  [{label}] Address index: enabled at /api/v2/");
    addr_index::api::routes(idx)
}

#[tokio::main]
async fn main() {
    let _ = dotenvy::dotenv();
    let config = config::Config::parse();

    eprintln!("╔══════════════════════════════════════════╗");
    eprintln!("║          PIVX Bridge v{}           ║", env!("CARGO_PKG_VERSION"));
    eprintln!("╠══════════════════════════════════════════╣");
    eprintln!("║  RPC:  {}  ", config.rpc_url);
    eprintln!("║  ZMQ:  {}  ", config.zmq_url);
    eprintln!("║  Port: {}                            ", config.port);
    eprintln!("╚══════════════════════════════════════════╝");

    let allowed_rpcs = config.allowed_rpc_set();

    // -- Mainnet --
    let mainnet_state = init_network(&NetworkConfig {
        label: "mainnet",
        rpc_url: &config.rpc_url,
        rpc_user: &config.rpc_user,
        rpc_pass: &config.rpc_pass,
        index_path: "shield_index.json",
        cache_path: "shield.bin",
        cursor_path: "shield_cursor.json",
        sapling_height: config.sapling_height,
        allowed_rpcs: allowed_rpcs.clone(),
    }).expect("mainnet initialization failed");

    let mainnet_index_path = "shield_index.json".to_string();
    spawn_zmq_listener(
        "mainnet",
        config.zmq_url.clone(),
        config.rpc_url.clone(), config.rpc_user.clone(), config.rpc_pass.clone(),
        mainnet_state.clone(),
        mainnet_index_path.clone(),
    );
    spawn_poller(
        "mainnet",
        config.rpc_url.clone(), config.rpc_user.clone(), config.rpc_pass.clone(),
        mainnet_state.clone(),
        mainnet_index_path,
    );

    let params_dir = sapling_params_dir(&config);
    match &params_dir {
        Some(d) => eprintln!("  Sapling params: serving from {}", d.display()),
        None => eprintln!("  Sapling params: not found (set SAPLING_PARAMS_DIR to serve them)"),
    }

    let mut mainnet_routes = build_routes(mainnet_state);
    if let Some(d) = &params_dir {
        mainnet_routes = mainnet_routes.merge(sapling_params_routes(d));
    }
    if config.addr_index {
        mainnet_routes = mainnet_routes.merge(start_addr_index(
            "mainnet",
            &config.addr_index_path,
            &config.rpc_url,
            &config.rpc_user,
            &config.rpc_pass,
        ));
    }

    // -- Router --
    let mut app = Router::new()
        .nest("/mainnet", mainnet_routes.clone())
        .merge(mainnet_routes);

    // -- Testnet (optional) --
    if let Some(testnet_url) = &config.testnet_rpc_url {
        let testnet_user = config.testnet_rpc_user.as_deref().unwrap_or(&config.rpc_user);
        let testnet_pass = config.testnet_rpc_pass.as_deref().unwrap_or(&config.rpc_pass);

        if let Some(testnet_state) = init_network(&NetworkConfig {
            label: "testnet",
            rpc_url: testnet_url,
            rpc_user: testnet_user,
            rpc_pass: testnet_pass,
            index_path: "shield_index.testnet.json",
            cache_path: "shield.testnet.bin",
            cursor_path: "shield_cursor.testnet.json",
            sapling_height: config.sapling_height,
            allowed_rpcs,
        }) {
            let testnet_index_path = "shield_index.testnet.json".to_string();
            spawn_zmq_listener(
                "testnet",
                config.zmq_url.clone(),
                testnet_url.clone(), testnet_user.to_string(), testnet_pass.to_string(),
                testnet_state.clone(),
                testnet_index_path.clone(),
            );
            spawn_poller(
                "testnet",
                testnet_url.clone(), testnet_user.to_string(), testnet_pass.to_string(),
                testnet_state.clone(),
                testnet_index_path,
            );

            let mut testnet_routes = build_routes(testnet_state);
            if let Some(d) = &params_dir {
                testnet_routes = testnet_routes.merge(sapling_params_routes(d));
            }
            if config.addr_index {
                testnet_routes = testnet_routes.merge(start_addr_index(
                    "testnet",
                    &config.testnet_addr_index_path,
                    testnet_url,
                    testnet_user,
                    testnet_pass,
                ));
            }
            app = app.nest("/testnet", testnet_routes);
            eprintln!("  Testnet: enabled at /testnet/");
        }
    }

    // -- Layers --
    let app = app.layer(CorsLayer::permissive());

    let app = if config.no_compression {
        eprintln!("  Compression: OFF");
        app.into_make_service()
    } else {
        eprintln!("  Compression: ON (gzip, best quality — disable with --no-compression)");
        app.layer(CompressionLayer::new().quality(CompressionLevel::Best))
            .into_make_service()
    };

    let addr = format!("0.0.0.0:{}", config.port);
    eprintln!("\n  Listening on http://{addr}");

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("failed to bind");

    axum::serve(listener, app).await.expect("server error");
}

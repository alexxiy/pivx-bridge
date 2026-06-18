/// Block JSON cache — caches `getblock` responses with reorg detection.
///
/// Strips mutable fields (`confirmations`, `nextblockhash`) on insert and
/// rehydrates them on read using the current chain height and height-to-hash
/// index. Evicts the lowest-height entry when full, keeping tip blocks hot.
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

/// Cached `getblock` response with mutable fields stripped.
struct CachedBlock {
    height: u32,
    /// JSON response with `confirmations` and `nextblockhash` removed.
    json: Value,
}

/// Thread-safe block cache with reorg-aware invalidation.
///
/// Read path (`get`) only needs a shared `&self` — hit/miss counters use
/// atomics. Write path (`insert`, `invalidate_from`) takes `&mut self`.
pub struct BlockCache {
    /// `(block_hash, verbosity)` -> stripped response.
    entries: HashMap<(String, u8), CachedBlock>,
    /// `height` -> `block_hash` for reverse lookups and reorg invalidation.
    height_to_hash: HashMap<u32, String>,
    capacity: usize,
    pub hits: AtomicU64,
    pub misses: AtomicU64,
}

impl BlockCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            height_to_hash: HashMap::with_capacity(capacity),
            capacity,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Look up a cached block, rehydrating `confirmations` and `nextblockhash`.
    ///
    /// Falls back to other verbosity levels on miss — a verbosity 2 response
    /// is a superset of verbosity 1, so serving it for a v1 request is safe.
    /// Read-only on the map — only atomics are mutated (hit/miss counters).
    pub fn get(&self, hash: &str, verbosity: u8, chain_height: u32) -> Option<Value> {
        let key = (hash.to_string(), verbosity);
        let entry = match self.entries.get(&key) {
            Some(e) => e,
            None => {
                // Verbosity fallback is safe in ONE direction only. A verbosity-2
                // response is a superset of verbosity-1, so a v1 request may be
                // served from a cached v2 entry. The reverse is NOT safe: a v1
                // response carries only txid strings (`.tx = ["<txid>", ...]`),
                // not the full transaction objects a v2 caller expects. Serving a
                // v1 entry for a v2 request returns a malformed block that breaks
                // consumers (e.g. MPW's `.tx[] | { hex: .hex }` jq filter fails
                // with "cannot index <txid> with hex"). v0 is raw hex, not JSON,
                // so it never participates. Only a v1 request may fall back (→v2);
                // any other miss must return None so the proxy fetches fresh.
                if verbosity != 1 {
                    self.misses.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
                match self.entries.get(&(hash.to_string(), 2u8)) {
                    Some(e) => e,
                    None => {
                        self.misses.fetch_add(1, Ordering::Relaxed);
                        return None;
                    }
                }
            }
        };

        self.hits.fetch_add(1, Ordering::Relaxed);

        let mut json = entry.json.clone();
        if let Some(obj) = json.as_object_mut() {
            // confirmations = chain_height - block_height + 1
            let confs = chain_height.saturating_sub(entry.height) + 1;
            obj.insert("confirmations".into(), Value::from(confs));

            // nextblockhash — present only if we know the successor
            if let Some(next_hash) = self.height_to_hash.get(&(entry.height + 1)) {
                obj.insert("nextblockhash".into(), Value::from(next_hash.as_str()));
            }
        }

        Some(json)
    }

    /// Cache a `getblock` response, stripping mutable fields.
    ///
    /// Duplicate inserts (same hash + verbosity) are no-ops.
    /// When at capacity, the lowest-height entry is evicted — this naturally
    /// keeps the tip blocks (hottest for light-wallet traffic) in the cache.
    pub fn insert(&mut self, hash: &str, verbosity: u8, json: &Value) {
        let key = (hash.to_string(), verbosity);
        if self.entries.contains_key(&key) {
            return;
        }

        let height = json
            .get("height")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        // Evict lowest-height entry if at capacity
        while self.entries.len() >= self.capacity {
            self.evict_lowest();
        }

        // Strip dynamic fields
        let mut stripped = json.clone();
        if let Some(obj) = stripped.as_object_mut() {
            obj.remove("confirmations");
            obj.remove("nextblockhash");
        }

        self.height_to_hash.insert(height, hash.to_string());
        self.entries.insert(key, CachedBlock { height, json: stripped });
    }

    /// Get the block hash for a given height (if cached).
    pub fn hash_for_height(&self, height: u32) -> Option<&str> {
        self.height_to_hash.get(&height).map(|s| s.as_str())
    }

    /// Check if a new block's `previousblockhash` diverges from our cache.
    pub fn detect_reorg(&self, height: u32, prev_hash: &str) -> bool {
        if height == 0 {
            return false;
        }
        match self.height_to_hash.get(&(height - 1)) {
            Some(cached) => cached != prev_hash,
            None => false,
        }
    }

    /// Invalidate all cached blocks at or above `fork_height`.
    pub fn invalidate_from(&mut self, fork_height: u32) {
        let to_remove: Vec<u32> = self
            .height_to_hash
            .keys()
            .copied()
            .filter(|&h| h >= fork_height)
            .collect();

        let count = to_remove.len();
        for h in to_remove {
            if let Some(hash) = self.height_to_hash.remove(&h) {
                for v in 0..=2u8 {
                    self.entries.remove(&(hash.clone(), v));
                }
            }
        }

        if count > 0 {
            eprintln!("  [block_cache] Invalidated {count} block(s) from height {fork_height}");
        }
    }

    /// Return `(hits, misses, cached_blocks)` for logging.
    pub fn stats(&self) -> (u64, u64, usize) {
        (
            self.hits.load(Ordering::Relaxed),
            self.misses.load(Ordering::Relaxed),
            self.height_to_hash.len(),
        )
    }

    /// Evict the entry with the lowest block height.
    fn evict_lowest(&mut self) {
        let min_height = match self.height_to_hash.keys().min().copied() {
            Some(h) => h,
            None => return,
        };
        if let Some(hash) = self.height_to_hash.remove(&min_height) {
            for v in 0..=2u8 {
                self.entries.remove(&(hash.clone(), v));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_block(height: u32, hash: &str) -> Value {
        json!({
            "hash": hash,
            "height": height,
            "confirmations": 100,
            "nextblockhash": "next_placeholder",
            "tx": ["txid1", "txid2"],
            "time": 1700000000u64 + height as u64,
        })
    }

    #[test]
    fn insert_and_get_rehydrates() {
        let mut cache = BlockCache::new(10);
        let block = make_block(500, "abc123");
        cache.insert("abc123", 1, &block);

        let got = cache.get("abc123", 1, 600).unwrap();
        assert_eq!(got["confirmations"], 101);
        assert!(got.get("nextblockhash").is_none());

        let block2 = make_block(501, "def456");
        cache.insert("def456", 1, &block2);
        let got = cache.get("abc123", 1, 600).unwrap();
        assert_eq!(got["nextblockhash"], "def456");
        assert_eq!(got["tx"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn miss_returns_none() {
        let cache = BlockCache::new(10);
        assert!(cache.get("nonexistent", 1, 100).is_none());
        assert_eq!(cache.misses.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn evicts_lowest_height() {
        let mut cache = BlockCache::new(3);
        cache.insert("a", 1, &make_block(100, "a"));
        cache.insert("b", 1, &make_block(200, "b"));
        cache.insert("c", 1, &make_block(300, "c"));
        cache.insert("d", 1, &make_block(400, "d"));
        assert!(cache.get("a", 1, 500).is_none());
        assert!(cache.get("b", 1, 500).is_some());
        assert!(cache.get("d", 1, 500).is_some());
    }

    #[test]
    fn reorg_detection_and_invalidation() {
        let mut cache = BlockCache::new(10);
        cache.insert("aaa", 1, &make_block(98, "aaa"));
        cache.insert("bbb", 1, &make_block(99, "bbb"));
        cache.insert("ccc", 1, &make_block(100, "ccc"));

        assert!(cache.detect_reorg(100, "different_parent"));
        assert!(!cache.detect_reorg(100, "bbb"));

        cache.invalidate_from(99);
        assert!(cache.get("aaa", 1, 200).is_some());
        assert!(cache.get("bbb", 1, 200).is_none());
        assert!(cache.get("ccc", 1, 200).is_none());
    }

    #[test]
    fn duplicate_insert_is_noop() {
        let mut cache = BlockCache::new(10);
        cache.insert("abc", 1, &make_block(100, "abc"));
        cache.insert("abc", 1, &make_block(100, "abc"));
        assert_eq!(cache.entries.len(), 1);
    }

    #[test]
    fn verbosity_fallback() {
        let mut cache = BlockCache::new(10);
        let block = make_block(100, "abc");

        // Insert at v2 only
        cache.insert("abc", 2, &block);
        assert_eq!(cache.entries.len(), 1);

        // v2 lookup: direct hit
        assert!(cache.get("abc", 2, 200).is_some());
        // v1 lookup: falls back to v2 (superset)
        assert!(cache.get("abc", 1, 200).is_some());
        // v0 lookup: no fallback (v0 is hex, not JSON)
        assert!(cache.get("abc", 0, 200).is_none());
    }

    #[test]
    fn v2_request_never_falls_back_to_v1() {
        // Regression: a v1 entry (txid strings, not full tx objects) must NEVER
        // satisfy a v2 request. The old bidirectional fallback served the v1
        // entry for v2 lookups, returning a malformed block (`.tx` = txid
        // strings) that broke `getblock ...,2` consumers (e.g. MPW's jq filter).
        let mut cache = BlockCache::new(10);
        cache.insert("def", 1, &make_block(101, "def"));

        // v1 direct hit is fine.
        assert!(cache.get("def", 1, 200).is_some());
        // v2 must miss (→ None) so the proxy re-fetches a real v2 block from the
        // node, rather than being served the v1 (string-tx) entry.
        assert!(cache.get("def", 2, 200).is_none());
    }
}

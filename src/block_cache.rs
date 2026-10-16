/// Block JSON cache — caches `getblock` responses with reorg detection.
///
/// Answers are kept serialized, without the fields that change
/// (`confirmations`, `nextblockhash`); those are put back on read from the
/// current chain height and the cached successor. A hit is a copy of the
/// bytes, not a parse. Evicts the lowest-height entry when over its count
/// or size limit, keeping tip blocks hot.
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::OnceLock;

use serde::ser::{Serialize, SerializeMap, Serializer};
use serde_json::{Map, Value};

/// Fields of a `getblock` answer that change as the chain grows.
const DYNAMIC: [&str; 2] = ["confirmations", "nextblockhash"];

/// One cached `getblock` answer.
pub struct Entry {
    height: u32,
    /// The answer's JSON object without [`DYNAMIC`].
    json: Vec<u8>,
    /// Of a verbosity-2 answer, made on first use: the verbosity-1 answer
    /// and MyPIVXWallet's filtered one (see [`MPW_BLOCK_FILTER`]).
    v1: OnceLock<Vec<u8>>,
    mpw: OnceLock<Vec<u8>>,
}

impl Entry {
    /// `block` (a `getblock` answer) to cache; `None` unless it's a block
    /// object with a height (raw hex answers aren't cached: they don't
    /// say their height).
    pub fn new(block: &Value) -> Option<Self> {
        let obj = block.as_object()?;
        let height = obj.get("height")?.as_u64()? as u32;
        let json = serde_json::to_vec(&Fields { obj, skip: &DYNAMIC, tx: None }).ok()?;
        Some(Self { height, json, v1: OnceLock::new(), mpw: OnceLock::new() })
    }

    fn size(&self) -> usize {
        self.json.len() + self.v1.get().map_or(0, Vec::len) + self.mpw.get().map_or(0, Vec::len)
    }
}

/// The filter MyPIVXWallet sends with `getblock <hash> 2` (canonical form,
/// see `proxy::known_filter`): only each transaction's hex and txid, as
/// `txs`. The cache answers it without running jq.
pub const MPW_BLOCK_FILTER: &str = ". | .txs = [.tx[] | { hex: .hex, txid: .txid}] | del(.tx)";

/// Which answer a request wants of a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Want {
    /// `getblock <hash> <verbosity>`.
    Verbosity(u8),
    /// `getblock <hash> 2` filtered by [`MPW_BLOCK_FILTER`].
    Mpw,
}

/// Serializes `obj` without the keys in `skip`, then `tx` if given.
struct Fields<'a> {
    obj: &'a Map<String, Value>,
    skip: &'a [&'a str],
    tx: Option<(&'a str, Value)>,
}

impl Serialize for Fields<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut map = s.serialize_map(None)?;
        for (k, v) in self.obj.iter().filter(|(k, _)| !self.skip.contains(&k.as_str())) {
            map.serialize_entry(k, v)?;
        }
        if let Some((k, v)) = &self.tx {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

/// The verbosity-1 answer (txids in `tx`) or MyPIVXWallet's (`txs` of hex
/// and txid) from a cached verbosity-2 `json`.
fn derive(json: &[u8], want: Want) -> Vec<u8> {
    let Ok(Value::Object(obj)) = serde_json::from_slice::<Value>(json) else { return json.to_vec() };
    let txs = obj.get("tx").and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
    let field = |t: &Value, k: &str| t.get(k).cloned().unwrap_or(Value::Null);
    let tx = match want {
        Want::Mpw => ("txs", txs.iter().map(|t| serde_json::json!({ "hex": field(t, "hex"), "txid": field(t, "txid") })).collect()),
        _ => ("tx", txs.iter().map(|t| field(t, "txid")).collect()),
    };
    serde_json::to_vec(&Fields { obj: &obj, skip: &["tx"], tx: Some(tx) }).unwrap_or_default()
}

/// `json` (an object without them) with `confirmations` and, when known,
/// `nextblockhash` put back.
fn with_dynamic(json: &[u8], confirmations: u32, next: Option<&str>) -> Vec<u8> {
    let mut out = Vec::with_capacity(json.len() + 110);
    out.push(b'{');
    out.extend_from_slice(format!("\"confirmations\":{confirmations},").as_bytes());
    if let Some(next) = next {
        out.extend_from_slice(format!("\"nextblockhash\":{},", Value::from(next)).as_bytes());
    }
    // Entries always hold at least `height`: never `{}`.
    out.extend_from_slice(&json[1..]);
    out
}

/// Thread-safe block cache with reorg-aware invalidation.
///
/// Read path (`get`) only needs a shared `&self` — counters are atomics.
/// Write path (`insert`, `invalidate_from`) takes `&mut self`.
pub struct BlockCache {
    /// `(block_hash, verbosity)` -> entry.
    entries: HashMap<(String, u8), Entry>,
    /// `height` -> `block_hash` for reverse lookups and reorg invalidation.
    height_to_hash: BTreeMap<u32, String>,
    capacity: usize,
    max_bytes: usize,
    /// Bytes held by the entries (derived answers are added when made).
    bytes: AtomicUsize,
    pub hits: AtomicU64,
    pub misses: AtomicU64,
}

impl BlockCache {
    /// Up to `capacity` answers and `max_bytes` of them.
    pub fn new(capacity: usize, max_bytes: usize) -> Self {
        Self {
            entries: HashMap::with_capacity(capacity),
            height_to_hash: BTreeMap::new(),
            capacity,
            max_bytes,
            bytes: AtomicUsize::new(0),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// A cached answer (JSON bytes), with `confirmations` and
    /// `nextblockhash` as of `chain_height`. A successor this cache doesn't
    /// hold is asked of `hash_at`; if that doesn't know it either, the
    /// answer can't be made (`None`), as the node's would name it.
    ///
    /// A v1 or MyPIVXWallet request is also served from a cached v2 block:
    /// v2 is v1 with each txid in `tx` expanded to the transaction. The
    /// reverse is NOT safe: a v1 answer carries only txid strings, not the
    /// transaction objects a v2 caller expects (MPW's `.tx[] | { hex: .hex }`
    /// filter fails with "cannot index <txid> with hex"), so a v2 miss
    /// goes to the node.
    pub fn get(&self, hash: &str, want: Want, chain_height: u32, hash_at: impl FnOnce(u32) -> Option<String>) -> Option<Vec<u8>> {
        let exact = match want {
            Want::Verbosity(v) => self.entries.get(&(hash.to_string(), v)),
            Want::Mpw => None,
        };
        let json = match exact {
            Some(entry) => Some((entry, entry.json.as_slice())),
            None if want == Want::Verbosity(1) || want == Want::Mpw => {
                self.entries.get(&(hash.to_string(), 2)).map(|entry| {
                    let cell = if want == Want::Mpw { &entry.mpw } else { &entry.v1 };
                    if cell.get().is_none() {
                        let made = derive(&entry.json, want);
                        let len = made.len();
                        if cell.set(made).is_ok() {
                            self.bytes.fetch_add(len, Ordering::Relaxed);
                        }
                    }
                    (entry, cell.get().unwrap().as_slice())
                })
            }
            None => None,
        };
        let next = json.and_then(|(entry, _)| {
            let h = entry.height + 1;
            match self.height_to_hash.get(&h) {
                Some(next) => Some(Some(next.clone())),
                None if entry.height < chain_height => hash_at(h).map(Some),
                None => Some(None),
            }
        });
        let (Some((entry, json)), Some(next)) = (json, next) else {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        self.hits.fetch_add(1, Ordering::Relaxed);
        let confirmations = chain_height.saturating_sub(entry.height) + 1;
        Some(with_dynamic(json, confirmations, next.as_deref()))
    }

    /// Cache a `getblock` answer (see [`Entry::new`]). Duplicate inserts
    /// are no-ops.
    #[cfg(test)]
    pub fn insert(&mut self, hash: &str, verbosity: u8, json: &Value) {
        if let Some(entry) = Entry::new(json) {
            self.insert_entry(hash, verbosity, entry);
        }
    }

    /// [`Self::insert`] of an entry made beforehand (off the lock).
    pub fn insert_entry(&mut self, hash: &str, verbosity: u8, entry: Entry) {
        let key = (hash.to_string(), verbosity);
        if self.entries.contains_key(&key) {
            return;
        }
        let height = entry.height;
        // Another block at this height (reorg): drop it, or its entries
        // would outlive their height mapping and never be evicted.
        if let Some(old) = self.height_to_hash.get(&height).filter(|h| h.as_str() != hash).cloned() {
            self.remove_block(&old);
        }
        *self.bytes.get_mut() += entry.size();
        self.height_to_hash.insert(height, hash.to_string());
        self.entries.insert(key, entry);
        while (self.entries.len() > self.capacity || *self.bytes.get_mut() > self.max_bytes) && self.height_to_hash.len() > 1 {
            let Some((_, lowest)) = self.height_to_hash.pop_first() else { break };
            self.remove_block(&lowest);
        }
    }

    fn remove_block(&mut self, hash: &str) {
        for v in 0..=2u8 {
            if let Some(entry) = self.entries.remove(&(hash.to_string(), v)) {
                *self.bytes.get_mut() -= entry.size();
            }
        }
    }

    /// Get the block hash for a given height (if cached).
    pub fn hash_for_height(&self, height: u32) -> Option<&str> {
        self.height_to_hash.get(&height).map(|s| s.as_str())
    }

    /// Invalidate all cached blocks at or above `fork_height`.
    pub fn invalidate_from(&mut self, fork_height: u32) {
        let gone = self.height_to_hash.split_off(&fork_height);
        for hash in gone.values() {
            self.remove_block(hash);
        }
        if !gone.is_empty() {
            log::info!("[block_cache] Invalidated {} block(s) from height {fork_height}", gone.len());
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

    fn get(cache: &BlockCache, hash: &str, verbosity: u8, chain_height: u32) -> Option<Value> {
        cache.get(hash, Want::Verbosity(verbosity), chain_height, unknown).map(|b| serde_json::from_slice(&b).unwrap())
    }

    /// Answers like the node's, so these tests ask about the tip block,
    /// or one whose successor is cached too.
    fn unknown(_: u32) -> Option<String> {
        None
    }

    #[test]
    fn insert_and_get_rehydrates() {
        let mut cache = BlockCache::new(10, 1 << 20);
        let block = make_block(500, "abc123");
        cache.insert("abc123", 1, &block);

        let got = get(&cache, "abc123", 1, 500).unwrap();
        assert_eq!(got["confirmations"], 1);
        assert!(got.get("nextblockhash").is_none());
        // Not the tip, successor unknown: the node's answer would name it.
        assert!(get(&cache, "abc123", 1, 600).is_none());
        let at = |h: u32| (h == 501).then(|| "known".to_string());
        let got: Value = serde_json::from_slice(&cache.get("abc123", Want::Verbosity(1), 600, at).unwrap()).unwrap();
        assert_eq!(got["nextblockhash"], "known");

        let block2 = make_block(501, "def456");
        cache.insert("def456", 1, &block2);
        let got = get(&cache, "abc123", 1, 600).unwrap();
        assert_eq!(got["nextblockhash"], "def456");
        assert_eq!(got["tx"].as_array().unwrap().len(), 2);
        assert_eq!(got["time"], 1700000500u64);
    }

    #[test]
    fn miss_returns_none() {
        let cache = BlockCache::new(10, 1 << 20);
        assert!(get(&cache, "nonexistent", 1, 100).is_none());
        assert_eq!(cache.misses.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn evicts_lowest_height() {
        let mut cache = BlockCache::new(3, 1 << 20);
        cache.insert("a", 1, &make_block(100, "a"));
        cache.insert("b", 1, &make_block(200, "b"));
        cache.insert("c", 1, &make_block(300, "c"));
        cache.insert("d", 1, &make_block(400, "d"));
        // (Each asked as the tip, so no successor is needed.)
        assert!(get(&cache, "a", 1, 100).is_none());
        assert!(get(&cache, "b", 1, 200).is_some());
        assert!(get(&cache, "d", 1, 400).is_some());
    }

    #[test]
    fn evicts_by_size() {
        let size = Entry::new(&make_block(100, "a")).unwrap().size();
        let mut cache = BlockCache::new(100, 2 * size);
        cache.insert("a", 1, &make_block(100, "a"));
        cache.insert("b", 1, &make_block(101, "b"));
        assert!(get(&cache, "a", 1, 102).is_some());
        cache.insert("c", 1, &make_block(102, "c"));
        assert!(get(&cache, "a", 1, 102).is_none());
        assert!(get(&cache, "c", 1, 102).is_some());
        assert_eq!(cache.bytes.load(Ordering::Relaxed), 2 * size);
        cache.invalidate_from(0);
        assert_eq!(cache.bytes.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn raw_answers_are_not_cached() {
        let mut cache = BlockCache::new(10, 1 << 20);
        cache.insert("abc", 0, &json!("0b000000"));
        assert!(get(&cache, "abc", 0, 100).is_none());
        assert_eq!(cache.hash_for_height(0), None);
    }

    #[test]
    fn reorg_detection_and_invalidation() {
        let mut cache = BlockCache::new(10, 1 << 20);
        cache.insert("aaa", 1, &make_block(98, "aaa"));
        cache.insert("bbb", 1, &make_block(99, "bbb"));
        cache.insert("ccc", 1, &make_block(100, "ccc"));

        cache.invalidate_from(99);
        assert!(get(&cache, "aaa", 1, 98).is_some());
        assert!(get(&cache, "bbb", 1, 98).is_none());
        assert!(get(&cache, "ccc", 1, 98).is_none());
    }

    #[test]
    fn duplicate_insert_is_noop() {
        let mut cache = BlockCache::new(10, 1 << 20);
        cache.insert("abc", 1, &make_block(100, "abc"));
        cache.insert("abc", 1, &make_block(100, "abc"));
        assert_eq!(cache.entries.len(), 1);
    }

    #[test]
    fn verbosity_fallback() {
        let mut cache = BlockCache::new(10, 1 << 20);
        let v2 = json!({ "hash": "abc", "height": 100, "tx": [{ "txid": "t1", "hex": "00", "vin": [] }, { "txid": "t2", "hex": "01" }] });

        // Insert at v2 only
        cache.insert("abc", 2, &v2);
        assert_eq!(cache.entries.len(), 1);

        // v2 lookup: direct hit, full transactions
        assert_eq!(get(&cache, "abc", 2, 100).unwrap()["tx"][0]["hex"], "00");
        // v1 lookup: answered from v2, with txids in `tx` like pivxd's v1
        let v1 = get(&cache, "abc", 1, 100).unwrap();
        assert_eq!(v1["tx"], json!(["t1", "t2"]));
        assert_eq!(v1["hash"], "abc");
        assert_eq!(v1["confirmations"], 1);
        // v0 lookup: no fallback (v0 is hex, not JSON)
        assert!(get(&cache, "abc", 0, 100).is_none());
    }

    #[test]
    fn mpw_filter_answered_from_v2() {
        let mut cache = BlockCache::new(10, 1 << 20);
        let v2 = json!({ "hash": "abc", "height": 100, "tx": [{ "txid": "t1", "hex": "00", "vin": [] }, { "txid": "t2" }] });
        cache.insert("abc", 2, &v2);
        cache.insert("def", 1, &make_block(101, "def"));
        let before = cache.bytes.load(Ordering::Relaxed);
        let got: Value = serde_json::from_slice(&cache.get("abc", Want::Mpw, 200, unknown).unwrap()).unwrap();
        // What jq gives for `. | .txs = [.tx[] | { hex: .hex, txid: .txid}] | del(.tx)`.
        let jq = crate::proxy::apply_jq(&get(&cache, "abc", 2, 200).unwrap(), MPW_BLOCK_FILTER).unwrap();
        assert_eq!(got, jq);
        assert_eq!(got["txs"], json!([{ "hex": "00", "txid": "t1" }, { "hex": null, "txid": "t2" }]));
        assert_eq!(got["nextblockhash"], "def");
        // Made once, then counted in the size.
        assert!(cache.bytes.load(Ordering::Relaxed) > before);
        assert_eq!(cache.get("abc", Want::Mpw, 200, unknown), cache.get("abc", Want::Mpw, 200, unknown));
        // A v1 entry can't answer it.
        assert!(cache.get("def", Want::Mpw, 200, unknown).is_none());
    }

    #[test]
    fn v2_request_never_falls_back_to_v1() {
        // Regression: a v1 entry (txid strings, not full tx objects) must NEVER
        // satisfy a v2 request. The old bidirectional fallback served the v1
        // entry for v2 lookups, returning a malformed block (`.tx` = txid
        // strings) that broke `getblock ...,2` consumers (e.g. MPW's jq filter).
        let mut cache = BlockCache::new(10, 1 << 20);
        cache.insert("def", 1, &make_block(101, "def"));

        // v1 direct hit is fine.
        assert!(get(&cache, "def", 1, 101).is_some());
        // v2 must miss (→ None) so the proxy re-fetches a real v2 block from the
        // node, rather than being served the v1 (string-tx) entry.
        assert!(get(&cache, "def", 2, 101).is_none());
    }

    #[test]
    fn replaced_block_at_height_is_dropped() {
        let mut cache = BlockCache::new(2, 1 << 20);
        cache.insert("old", 1, &make_block(100, "old"));
        cache.insert("new", 1, &make_block(100, "new"));
        assert!(get(&cache, "old", 1, 100).is_none());
        assert_eq!(cache.hash_for_height(100), Some("new"));
        // Stays within capacity (no stranded entries).
        cache.insert("a", 1, &make_block(101, "a"));
        cache.insert("b", 1, &make_block(102, "b"));
        assert!(cache.entries.len() <= 2);
    }
}

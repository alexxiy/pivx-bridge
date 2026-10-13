/// HTTP API — axum endpoints for the PIVX bridge.
///
/// All routes are also served under `/mainnet/` for PivxNodeController
/// compatibility.
use std::io::{Read, Seek, SeekFrom};
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, RwLock};

use axum::body::{Body, Bytes};
use axum::extract::{Query, State};
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::Response;
use axum::Json;
use serde::Deserialize;

use crate::block_cache::BlockCache;
use crate::proxy::JqPolicy;
use crate::rpc::RpcClient;
use crate::shield_store::ShieldStore;
use crate::stream;

/// Shared application state.
pub struct AppState {
    pub label: &'static str,
    pub rpc: RpcClient,
    /// shield.bin + its index; shield data is streamed from disk.
    pub store: ShieldStore,
    pub allowed_rpcs: Vec<String>,
    /// LRU cache: height → block hash. Eliminates redundant getblockhash RPCs.
    pub hash_cache: RwLock<HashCache>,
    /// Block JSON cache: `(hash, verbosity)` → stripped response.
    /// Eliminates repeated `getblock` RPCs for the same blocks.
    pub block_cache: RwLock<BlockCache>,
    /// Node tip as last seen by the shield indexer.
    pub chain_height: AtomicU32,
    pub jq: JqPolicy,
}

/// Fixed-size LRU cache for block height → hash mappings.
pub struct HashCache {
    entries: std::collections::HashMap<u32, String>,
    order: std::collections::VecDeque<u32>,
    capacity: usize,
}

impl HashCache {
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: std::collections::HashMap::with_capacity(capacity),
            order: std::collections::VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub fn get(&self, height: u32) -> Option<&str> {
        self.entries.get(&height).map(|s| s.as_str())
    }

    pub fn insert(&mut self, height: u32, hash: String) {
        if let Some(old) = self.entries.get_mut(&height) {
            *old = hash;
            return;
        }
        if self.entries.len() >= self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
        self.entries.insert(height, hash);
        self.order.push_back(height);
    }

    /// Forget heights at or above `fork` (they were reorganised away).
    pub fn invalidate_from(&mut self, fork: u32) {
        self.entries.retain(|&h, _| h < fork);
        self.order.retain(|&h| h < fork);
    }
}

/// Run blocking work (RPC, disk) off the async workers.
pub async fn blocking<T, F>(f: F) -> Result<T, (StatusCode, String)>
where
    F: FnOnce() -> Result<T, (StatusCode, String)> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
}

fn internal(e: String) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e)
}

// ---------------------------------------------------------------------------
// Stream format
// ---------------------------------------------------------------------------

/// Stream format for the shield sync protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum StreamFormat {
    /// PIVX-compatible (default): 0x03 full raw tx + 0x5d block footer with time.
    /// Byte-identical to PivxNodeController. MPW parses this unchanged.
    #[default]
    #[serde(rename = "pivx")]
    PivxCompat,
    /// Compact (0x04): strips proofs/sigs, keeps out_ciphertext (724 bytes/output).
    Compact,
    /// Compact+ (0x05): strips out_ciphertext too (644 bytes/output).
    #[serde(rename = "compactplus")]
    CompactPlus,
}

// ---------------------------------------------------------------------------
// GET /getshielddata?startBlock=N&format=...
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ShieldDataQuery {
    #[serde(rename = "startBlock")]
    pub start_block: Option<u32>,
    #[serde(default)]
    pub format: StreamFormat,
}

/// Bytes read from shield.bin per step while streaming.
const CHUNK: u64 = 1 << 20;

/// A binary response of `len` bytes (also in X-Content-Length, as
/// PivxNodeController sends it).
fn binary_response(body: Body, len: u64) -> Response {
    let mut resp = Response::new(body);
    let headers = resp.headers_mut();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(len));
    headers.insert("X-Content-Length", HeaderValue::from(len));
    resp
}

struct StreamReader {
    state: Arc<AppState>,
    file: Option<std::fs::File>,
    /// Remaining PIVX-compat bytes to read.
    left: u64,
    format: StreamFormat,
    generation: u64,
    /// Compact formats: bytes of a block not yet complete.
    carry: Vec<u8>,
}

impl StreamReader {
    async fn next_chunk(mut self) -> Option<(std::io::Result<Bytes>, Option<Self>)> {
        if self.left == 0 {
            return None;
        }
        let n = self.left.min(CHUNK) as usize;
        let mut file = self.file.take()?;
        let read = tokio::task::spawn_blocking(move || {
            let mut buf = vec![0u8; n];
            file.read_exact(&mut buf).map(|_| (file, buf))
        })
        .await
        .map_err(std::io::Error::other)
        .and_then(|r| r);
        let (file, buf) = match read {
            Ok(v) => v,
            Err(e) => return Some((Err(e), None)),
        };
        // A reorg cut shield.bin while we read: these bytes may be stale.
        if self.state.store.generation() != self.generation {
            return Some((Err(std::io::Error::other("shield data changed (chain reorganisation), retry")), None));
        }
        self.file = Some(file);
        self.left -= n as u64;
        let out = match self.format {
            StreamFormat::PivxCompat => Bytes::from(buf),
            format => {
                self.carry.extend_from_slice(&buf);
                let complete = stream::complete_blocks_len(&self.carry);
                let out = stream::pivxcompat_to_compact(&self.carry[..complete], format);
                self.carry.drain(..complete);
                Bytes::from(out)
            }
        };
        Some((Ok(out), Some(self)))
    }
}

/// Serve shield data from `startBlock` on, streamed from shield.bin.
///
/// Compact formats are derived block by block from the PIVX-compat bytes.
pub async fn get_shield_data(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ShieldDataQuery>,
) -> Result<Response, (StatusCode, String)> {
    let start = query.start_block.unwrap_or(0);
    let format = query.format;
    let snapshot = state.store.snapshot();
    let from = state.store.offsets_from(start).map_err(internal)?;
    let Some(from) = from else {
        return Ok(binary_response(Body::empty(), 0));
    };
    let pivx_len = snapshot.lengths.pivx.saturating_sub(from.pivx);
    let out_len = snapshot.lengths.of(format).saturating_sub(from.of(format));
    if pivx_len == 0 {
        return Ok(binary_response(Body::empty(), 0));
    }

    let s = state.clone();
    let file = blocking(move || {
        let mut f = s.store.open_reader().map_err(|e| internal(e.to_string()))?;
        f.seek(SeekFrom::Start(from.pivx)).map_err(|e| internal(e.to_string()))?;
        Ok(f)
    })
    .await?;

    let reader = StreamReader {
        state,
        file: Some(file),
        left: pivx_len,
        format,
        generation: snapshot.generation,
        carry: Vec::new(),
    };
    let body = Body::from_stream(futures::stream::unfold(Some(reader), |r| async move { r?.next_chunk().await }));
    Ok(binary_response(body, out_len))
}

// ---------------------------------------------------------------------------
// GET /getshielddatalength?startBlock=N&endBlock=M
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ShieldDataLengthQuery {
    #[serde(rename = "startBlock")]
    pub start_block: Option<u32>,
    #[serde(rename = "endBlock")]
    pub end_block: Option<u32>,
    #[serde(default)]
    pub format: StreamFormat,
}

/// Byte count of the shield data between two block heights (inclusive),
/// in the requested format. Used by MPW for sync progress bars.
pub async fn get_shield_data_length(
    State(state): State<Arc<AppState>>,
    Query(query): Query<ShieldDataLengthQuery>,
) -> Result<String, (StatusCode, String)> {
    let start = query.start_block.unwrap_or(0);
    let end = query.end_block.unwrap_or(u32::MAX);
    let snapshot = state.store.snapshot();
    let length = match state.store.offsets_from(start).map_err(internal)? {
        Some(from) if start <= end => {
            let to = state.store.offsets_after(end, &snapshot).map_err(internal)?;
            to.of(query.format).saturating_sub(from.of(query.format))
        }
        _ => 0,
    };
    Ok(length.to_string())
}

// ---------------------------------------------------------------------------
// GET /getblockcount
// ---------------------------------------------------------------------------

/// Return the current block height from the node.
pub async fn get_block_count(State(state): State<Arc<AppState>>) -> Result<String, (StatusCode, String)> {
    blocking(move || {
        state
            .rpc
            .get_block_count()
            .map(|c| c.to_string())
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("node error: {e}")))
    })
    .await
}

// ---------------------------------------------------------------------------
// GET /getshieldblocks
// ---------------------------------------------------------------------------

/// Return a JSON array of all shield block heights.
pub async fn get_shield_blocks(State(state): State<Arc<AppState>>) -> Result<Json<Vec<u32>>, (StatusCode, String)> {
    blocking(move || state.store.heights().map(Json).map_err(internal)).await
}

// ---------------------------------------------------------------------------
// POST /sendrawtransaction (body = hex string)
// ---------------------------------------------------------------------------

/// Broadcast a raw transaction to the network.
pub async fn send_raw_transaction(
    State(state): State<Arc<AppState>>,
    body: String,
) -> Result<String, (StatusCode, String)> {
    let hex = body.trim().to_string();
    if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err((StatusCode::BAD_REQUEST, "invalid transaction hex".into()));
    }
    eprintln!("  [broadcast] Received tx hex ({} bytes)", hex.len());
    blocking(move || match state.rpc.send_raw_transaction(&hex) {
        Ok(txid) => {
            eprintln!("  [broadcast] Success: {txid}");
            Ok(txid)
        }
        Err(e) => {
            eprintln!("  [broadcast] FAILED: {e}");
            Err((StatusCode::BAD_REQUEST, e))
        }
    })
    .await
}

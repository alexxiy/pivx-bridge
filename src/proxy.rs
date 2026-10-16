/// RPC proxy — forwards allowed RPC calls to the PIVX node with optional jq filtering.
///
/// PivxNodeController exposes `GET /mainnet/:method?params=a,b,c&filter=<jq>`.
/// MPW uses this for governance queries (getbudgetinfo, listmasternodes, etc).
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::Value;

use crate::api::AppState;
use crate::block_cache::{Entry, Want, MPW_BLOCK_FILTER};

#[derive(Deserialize, Default)]
pub struct ProxyQuery {
    /// Comma-separated RPC parameters. Numbers and booleans are type-coerced.
    pub params: Option<String>,
    /// jq-style filter expression applied to the RPC result.
    pub filter: Option<String>,
}

/// Which jq filters the proxy runs (`JQ_FILTERS`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum JqMode {
    /// Only the filters MyPIVXWallet and PIVXie send.
    Known,
    /// Any filter. A filter can loop forever or build huge values, so
    /// only for bridges that trusted clients use.
    Any,
    /// No filters.
    Off,
}

/// jq filter settings + a cap on filters running at once.
pub struct JqPolicy {
    pub mode: JqMode,
    pub running: tokio::sync::Semaphore,
}

impl JqPolicy {
    pub fn new(mode: JqMode) -> Self {
        Self { mode, running: tokio::sync::Semaphore::new(2) }
    }

    /// The filter to run for `expr`, or why it is refused.
    fn accept(&self, expr: &str) -> Result<String, String> {
        match self.mode {
            JqMode::Off => Err("jq filters are disabled on this bridge".into()),
            JqMode::Any if expr.len() > 10_000 => Err("filter expression too long".into()),
            // Known filters in their canonical form, so the block cache
            // still answers MyPIVXWallet's.
            JqMode::Any => Ok(known_filter(expr).unwrap_or_else(|| expr.to_string())),
            JqMode::Known => known_filter(expr).ok_or_else(|| "filter not allowed on this bridge".into()),
        }
    }
}

/// Handle RPC proxy requests: `GET /mainnet/:method?params=...&filter=...`
pub async fn rpc_proxy(
    State(state): State<Arc<AppState>>,
    Path(method): Path<String>,
    Query(query): Query<ProxyQuery>,
) -> Result<Response, (StatusCode, String)> {
    // Validate method against whitelist
    if !state.allowed_rpcs.iter().any(|r| r == &method) {
        return Err((StatusCode::FORBIDDEN, format!("RPC method '{method}' not allowed")));
    }
    let filter = match query.filter.as_deref() {
        Some(expr) if !expr.is_empty() => Some(state.jq.accept(expr).map_err(|e| (StatusCode::BAD_REQUEST, e))?),
        _ => None,
    };

    // Parse params with type coercion (PivxNodeController compat)
    let params = parse_params(query.params.as_deref().unwrap_or(""));
    let start = std::time::Instant::now();

    // Fast path: serve getblockhash from cache
    if method == "getblockhash" {
        if let Some(height) = params.first().and_then(|v| v.as_u64()).map(|h| h as u32) {
            let cached = state.hash_cache.read().unwrap().get(height).map(|h| h.to_string());
            if let Some(hash) = cached {
                log_timing(start, &method);
                return Ok(Json(Value::String(hash)).into_response());
            }
        }
    }

    // What a getblock request wants of the block cache: MyPIVXWallet's
    // filter is answered from it too, without jq.
    let want = (method == "getblock").then(|| {
        let verbosity = block_verbosity(&params);
        match filter.as_deref() {
            Some(MPW_BLOCK_FILTER) if verbosity == 2 => Want::Mpw,
            _ => Want::Verbosity(verbosity),
        }
    });

    // Fast path: serve getblock from block cache (then apply jq filter if needed)
    if let Some(want) = want {
        // First param can be a hash (string) or height (number) — resolve to hash
        let block_hash = if let Some(hash) = params.first().and_then(|v| v.as_str()) {
            Some(hash.to_string())
        } else if let Some(height) = params.first().and_then(|v| v.as_u64()).map(|h| h as u32) {
            let cache = state.block_cache.read().unwrap();
            cache.hash_for_height(height).map(String::from)
        } else {
            None
        };

        if let Some(hash) = &block_hash {
            let chain_h = state.chain_height.load(std::sync::atomic::Ordering::Relaxed);
            let cached = state.block_cache.read().unwrap().get(hash, want, chain_h, |h| successor(&state, h));
            if let Some(json) = cached {
                log_timing(start, &method);
                return filtered_bytes(&state, json, want, filter.as_deref()).await;
            }
        }
    }

    // Call the node
    let result = {
        let (state, method, params) = (state.clone(), method.clone(), params.clone());
        let limit = state.node_calls.clone();
        crate::api::node_call(&limit, move || state.rpc.proxy_call(&method, &params).map_err(|e| (StatusCode::BAD_GATEWAY, e)))
            .await?
    };

    // Populate caches for getblockhash and getblock responses
    if method == "getblockhash" {
        if let (Some(height), Some(hash)) = (
            params.first().and_then(|v| v.as_u64()).map(|h| h as u32),
            result.as_str(),
        ) {
            state.hash_cache.write().unwrap().insert(height, hash.to_string());
        }
    } else if let Some(want) = want {
        // Only blocks on the main chain (an orphan has confirmations -1).
        let on_chain = result.get("confirmations").and_then(|v| v.as_i64()).is_some_and(|c| c > 0);
        if let (true, Some(height), Some(hash)) = (
            on_chain,
            result.get("height").and_then(|v| v.as_u64()).map(|h| h as u32),
            result.get("hash").and_then(|v| v.as_str()),
        ) {
            state.hash_cache.write().unwrap().insert(height, hash.to_string());
            if let Some(entry) = Entry::new(&result) {
                let chain_h = state.chain_height.load(std::sync::atomic::Ordering::Relaxed).max(height);
                let mut cache = state.block_cache.write().unwrap();
                cache.insert_entry(hash, block_verbosity(&params), entry);
                if want == Want::Mpw {
                    if let Some(json) = cache.get(hash, want, chain_h, |h| successor(&state, h)) {
                        drop(cache);
                        log_timing(start, &method);
                        return Ok(json_response(json));
                    }
                }
            }
        }
    }

    let filtered = run_filter(&state, result, filter.as_deref()).await?;

    // Log timing + cache stats for getblock
    if method == "getblock" && log::log_enabled!(log::Level::Debug) {
        let (hits, misses, cached) = state.block_cache.read().unwrap().stats();
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        let total = hits + misses;
        if ms >= 1.0 {
            log::debug!("[proxy {ms:.0}ms] {method} (cache: {hits}/{total} hits, {cached} blocks)");
        } else {
            log::debug!("[proxy {ms:.2}ms] {method} (cache: {hits}/{total} hits, {cached} blocks)");
        }
    } else {
        log_timing(start, &method);
    }
    Ok(Json(filtered).into_response())
}

/// The hash of block `height` if known without the node: for a cached
/// block's `nextblockhash`.
fn successor(state: &AppState, height: u32) -> Option<String> {
    let cached = state.hash_cache.read().unwrap().get(height).map(str::to_string);
    cached.or_else(|| state.store.hash_at(height).ok().flatten())
}

/// A JSON answer already serialized.
fn json_response(json: Vec<u8>) -> Response {
    ([(header::CONTENT_TYPE, "application/json")], json).into_response()
}

/// A cached block answer: as it is, or through a jq filter other than
/// MyPIVXWallet's.
async fn filtered_bytes(state: &Arc<AppState>, json: Vec<u8>, want: Want, filter: Option<&str>) -> Result<Response, (StatusCode, String)> {
    if want == Want::Mpw || filter.is_none() {
        return Ok(json_response(json));
    }
    let value = serde_json::from_slice(&json).map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(run_filter(state, value, filter).await?).into_response())
}

/// `getblock`'s verbosity as pivxd reads it: a number (0 or less is hex,
/// 2 or more includes the transactions) or a boolean (`false` is hex).
fn block_verbosity(params: &[Value]) -> u8 {
    match params.get(1) {
        None => 1,
        Some(Value::Bool(verbose)) => u8::from(*verbose),
        Some(v) => match v.as_i64() {
            Some(n) if n <= 0 => 0,
            Some(1) => 1,
            Some(_) => 2,
            None => 1,
        },
    }
}

/// Apply an accepted jq filter off the async workers, at most two at once.
async fn run_filter(state: &Arc<AppState>, value: Value, filter: Option<&str>) -> Result<Value, (StatusCode, String)> {
    let Some(expr) = filter else { return Ok(value) };
    let _permit = state.jq.running.acquire().await.map_err(|e| (StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;
    let expr = expr.to_string();
    crate::api::blocking(move || {
        apply_jq(&value, &expr).map_err(|e| (StatusCode::BAD_REQUEST, format!("jq filter error: {e}")))
    })
    .await
}

// ---------------------------------------------------------------------------
// Known filters
// ---------------------------------------------------------------------------

/// Canonical form of a filter MyPIVXWallet or PIVXie sends, or `None`:
///   - MPW getBlock: `. | .txs = [.tx[] | { hex: .hex, txid: .txid}] | del(.tx)`
///   - MPW vote lookup: `.[] | select(.mnId=="<txid>-<n>")`
///   - PIVXie vote lookup: `[.[] | select(.mnId == "<txid>-<n>" or ...)]`
///
/// Whitespace outside strings is ignored.
fn known_filter(expr: &str) -> Option<String> {
    let s = strip_whitespace(expr)?;
    if s == ".|.txs=[.tx[]|{hex:.hex,txid:.txid}]|del(.tx)" {
        return Some(MPW_BLOCK_FILTER.into());
    }
    if let Some(ids) = s.strip_prefix(".[]|select(").and_then(|r| r.strip_suffix(')')).and_then(mn_id_clauses) {
        return Some(format!(".[] | select({ids})"));
    }
    if let Some(ids) = s.strip_prefix("[.[]|select(").and_then(|r| r.strip_suffix(")]")).and_then(mn_id_clauses) {
        return Some(format!("[.[] | select({ids})]"));
    }
    None
}

/// `.mnId=="<id>"` clauses joined by `or`, rebuilt in canonical form.
fn mn_id_clauses(s: &str) -> Option<String> {
    let mut rest = s;
    let mut clauses = Vec::new();
    loop {
        let r = rest.strip_prefix(".mnId==\"")?;
        let q = r.find('"')?;
        let id = &r[..q];
        let (txid, n) = id.split_once('-')?;
        let valid = txid.len() == 64
            && txid.bytes().all(|b| b.is_ascii_hexdigit())
            && (1..=5).contains(&n.len())
            && n.bytes().all(|b| b.is_ascii_digit());
        if !valid || clauses.len() >= 1_000 {
            return None;
        }
        clauses.push(format!(".mnId == \"{id}\""));
        rest = &r[q + 1..];
        if rest.is_empty() {
            return Some(clauses.join(" or "));
        }
        rest = rest.strip_prefix("or")?;
    }
}

/// `expr` without whitespace outside string literals (`None` when a
/// string is not closed).
fn strip_whitespace(expr: &str) -> Option<String> {
    let mut out = String::with_capacity(expr.len());
    let mut in_string = false;
    let mut escaped = false;
    for c in expr.chars() {
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
            out.push(c);
        } else if !c.is_whitespace() {
            out.push(c);
        }
    }
    (!in_string).then_some(out)
}

/// Log (debug) how long a proxy call took.
pub fn log_timing(start: std::time::Instant, label: &str) {
    let ms = start.elapsed().as_secs_f64() * 1000.0;
    if ms >= 1000.0 {
        log::debug!("[proxy {:.1}s] {label}", ms / 1000.0);
    } else if ms >= 1.0 {
        log::debug!("[proxy {:.0}ms] {label}", ms);
    } else {
        log::debug!("[proxy {:.2}ms] {label}", ms);
    }
}

/// Parse comma-separated params with PivxNodeController-style type coercion.
///
/// Each param is tried as: integer → float → boolean → string.
///
/// A JSON array (`[...]`) is taken as is, for values that contain commas
/// (e.g. budget proposal names) or need an exact type.
fn parse_params(raw: &str) -> Vec<Value> {
    if raw.is_empty() {
        return Vec::new();
    }
    if raw.trim_start().starts_with('[') {
        if let Ok(Value::Array(values)) = serde_json::from_str::<Value>(raw) {
            return values;
        }
    }

    raw.split(',')
        .map(|s| {
            let s = s.trim();
            // Try integer
            if let Ok(n) = s.parse::<i64>() {
                return Value::Number(n.into());
            }
            // Try float
            if let Ok(f) = s.parse::<f64>() {
                if let Some(n) = serde_json::Number::from_f64(f) {
                    return Value::Number(n);
                }
            }
            // Try boolean
            match s {
                "true" => return Value::Bool(true),
                "false" => return Value::Bool(false),
                _ => {}
            }
            // String
            Value::String(s.to_string())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Inline jq filter — pure Rust via jaq, with compiled filter caching
// ---------------------------------------------------------------------------

type JaqNative = jaq_core::Native<jaq_core::data::JustLut<jaq_json::Val>>;
type JaqFilter = jaq_core::compile::Filter<JaqNative>;

/// Compiled filter cache — each unique expression is compiled once and reused.
static FILTER_CACHE: std::sync::LazyLock<std::sync::Mutex<std::collections::HashMap<String, Arc<JaqFilter>>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

/// Get a compiled filter from cache, or compile and cache it.
fn get_compiled_filter(expr: &str) -> Result<Arc<JaqFilter>, String> {
    let mut cache = FILTER_CACHE.lock().unwrap();
    if let Some(compiled) = cache.get(expr) {
        return Ok(compiled.clone());
    }

    let program = jaq_core::load::File { code: expr, path: () };
    let defs = jaq_core::defs().chain(jaq_std::defs()).chain(jaq_json::defs());
    type D = jaq_core::data::JustLut<jaq_json::Val>;
    let funs = jaq_core::funs::<D>().chain(jaq_std::funs()).chain(jaq_json::funs());

    let arena = jaq_core::load::Arena::default();
    let loader = jaq_core::load::Loader::new(defs);
    let modules = loader.load(&arena, program)
        .map_err(|errs| format!("jq parse: {errs:?}"))?;
    let compiled = jaq_core::Compiler::default()
        .with_funs(funs)
        .compile(modules)
        .map_err(|errs| format!("jq compile: {errs:?}"))?;

    let compiled = Arc::new(compiled);
    // Vote filters differ per masternode set: keep the cache bounded.
    if cache.len() >= 256 {
        cache.clear();
    }
    cache.insert(expr.to_string(), compiled.clone());
    Ok(compiled)
}

/// Apply a jq filter expression to a JSON value using jaq (pure Rust).
///
/// Filter compilation is cached — first call compiles, subsequent calls reuse.
pub(crate) fn apply_jq(value: &Value, expr: &str) -> Result<Value, String> {
    let compiled = get_compiled_filter(expr)?;

    // Parse input: serde_json::Value → string → jaq Val
    let input_str = serde_json::to_string(value).map_err(|e| e.to_string())?;
    let input: jaq_json::Val = jaq_json::read::parse_single(input_str.as_bytes())
        .map_err(|e| format!("jq input: {e}"))?;

    // Run cached compiled filter
    type D = jaq_core::data::JustLut<jaq_json::Val>;
    let ctx: jaq_core::Ctx<'_, D> = jaq_core::Ctx::new(&compiled.lut, jaq_core::Vars::new([]));
    let results: Vec<jaq_json::Val> = compiled.id.run((ctx, input))
        .map(|r: Result<jaq_json::Val, _>| r.map_err(|e| format!("jq eval: {e:?}")))
        .collect::<Result<Vec<_>, _>>()?;

    // Convert results: jaq Val → string → serde_json::Value
    if results.len() == 1 {
        let s = results[0].to_string();
        serde_json::from_str(&s).map_err(|e| format!("jq output: {e}"))
    } else {
        let values: Result<Vec<Value>, _> = results.iter()
            .map(|v: &jaq_json::Val| serde_json::from_str(&v.to_string()))
            .collect();
        Ok(Value::Array(values.map_err(|e| format!("jq output: {e}"))?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_params_empty() {
        assert_eq!(parse_params(""), Vec::<Value>::new());
    }

    #[test]
    fn parse_params_json_array() {
        let params = parse_params(r#"["Name, with comma", 1, "042"]"#);
        assert_eq!(
            params,
            vec![
                Value::String("Name, with comma".into()),
                Value::Number(1.into()),
                Value::String("042".into()),
            ]
        );
        // Not valid JSON: plain comma splitting.
        assert_eq!(parse_params("[a,b").len(), 2);
    }

    #[test]
    fn parse_params_types() {
        let params = parse_params("42,2.5,true,hello");
        assert_eq!(params[0], json!(42));
        assert_eq!(params[1], json!(2.5));
        assert_eq!(params[2], json!(true));
        assert_eq!(params[3], json!("hello"));
    }

    #[test]
    fn getblock_verbosity_like_pivxd() {
        let v = |p: &str| block_verbosity(&parse_params(p));
        assert_eq!(v("abc"), 1);
        assert_eq!(v("abc,false"), 0);
        assert_eq!(v("abc,true"), 1);
        assert_eq!(v("abc,0"), 0);
        assert_eq!(v("abc,-1"), 0);
        assert_eq!(v("abc,2"), 2);
        assert_eq!(v("abc,5"), 2);
    }

    #[test]
    fn jq_identity() {
        let v = json!({"a": 1});
        assert_eq!(apply_jq(&v, ".").unwrap(), v);
    }

    #[test]
    fn jq_field_access() {
        let v = json!({"name": "test", "value": 42});
        assert_eq!(apply_jq(&v, ".name").unwrap(), json!("test"));
        assert_eq!(apply_jq(&v, ".value").unwrap(), json!(42));
    }

    #[test]
    fn jq_nested_field() {
        let v = json!({"a": {"b": {"c": 99}}});
        assert_eq!(apply_jq(&v, ".a.b.c").unwrap(), json!(99));
    }

    #[test]
    fn jq_pipe() {
        let v = json!({"data": [1, 2, 3]});
        assert_eq!(apply_jq(&v, ".data | .[]").unwrap(), json!([1, 2, 3]));
    }

    #[test]
    fn jq_object_construction() {
        let v = json!({"name": "Alice", "age": 30, "extra": "skip"});
        assert_eq!(apply_jq(&v, "{name, age}").unwrap(), json!({"name": "Alice", "age": 30}));
    }

    #[test]
    fn jq_complex_assignment() {
        // The expression MPW actually uses
        let v = json!({"tx": [{"hex": "abc", "txid": "123", "extra": true}]});
        let result = apply_jq(&v, ". | .txs = [.tx[] | { hex: .hex, txid: .txid}] | del(.tx)").unwrap();
        assert_eq!(result, json!({"txs": [{"hex": "abc", "txid": "123"}]}));
    }

    #[test]
    fn known_filters_accepted() {
        let id = format!("{}-1", "ab".repeat(32));
        assert_eq!(
            known_filter(". | .txs = [.tx[] | { hex: .hex, txid: .txid}] | del(.tx)").as_deref(),
            Some(". | .txs = [.tx[] | { hex: .hex, txid: .txid}] | del(.tx)")
        );
        assert_eq!(
            known_filter(&format!(".[] | select(.mnId==\"{id}\")")),
            Some(format!(".[] | select(.mnId == \"{id}\")"))
        );
        let two = format!("[.[] | select(.mnId == \"{id}\" or .mnId == \"{id}\")]");
        assert_eq!(known_filter(&two), Some(two.clone()));
        // The canonical form runs.
        let votes = json!([{"mnId": id, "Vote": "YES"}, {"mnId": "x-0", "Vote": "NO"}]);
        assert_eq!(apply_jq(&votes, &known_filter(&two).unwrap()).unwrap(), json!([{"mnId": id, "Vote": "YES"}]));
    }

    #[test]
    fn other_filters_refused() {
        for f in ["def f: f; f", "[range(1e12)]", ".[] | select(.mnId==\"x\")", "..", "[.[] | select(.mnId == \"a\" or true)]"] {
            assert_eq!(known_filter(f), None, "{f}");
        }
        assert!(JqPolicy::new(JqMode::Off).accept(".").is_err());
        assert!(JqPolicy::new(JqMode::Any).accept(".a").is_ok());
    }
}

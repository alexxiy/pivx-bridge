/// RPC proxy — forwards allowed RPC calls to the PIVX node with optional jq filtering.
///
/// PivxNodeController exposes `GET /mainnet/:method?params=a,b,c&filter=<jq>`.
/// MPW uses this for governance queries (getbudgetinfo, listmasternodes, etc).
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use serde_json::Value;

use crate::api::AppState;

#[derive(Deserialize, Default)]
pub struct ProxyQuery {
    /// Comma-separated RPC parameters. Numbers and booleans are type-coerced.
    pub params: Option<String>,
    /// jq-style filter expression applied to the RPC result.
    pub filter: Option<String>,
}

/// Handle RPC proxy requests: `GET /mainnet/:method?params=...&filter=...`
pub async fn rpc_proxy(
    State(state): State<Arc<AppState>>,
    Path(method): Path<String>,
    Query(query): Query<ProxyQuery>,
) -> Result<Json<Value>, (StatusCode, String)> {
    // Validate method against whitelist
    if !state.allowed_rpcs.iter().any(|r| r == &method) {
        return Err((StatusCode::FORBIDDEN, format!("RPC method '{method}' not allowed")));
    }

    // Parse params with type coercion (PivxNodeController compat)
    let params = parse_params(query.params.as_deref().unwrap_or(""));
    let start = std::time::Instant::now();

    // Fast path: serve getblockhash from cache
    if method == "getblockhash" {
        if let Some(height) = params.first().and_then(|v| v.as_u64()).map(|h| h as u32) {
            let cache = state.hash_cache.read().await;
            if let Some(hash) = cache.get(height) {
                let result = Json(Value::String(hash.to_string()));
                log_timing(start, &method);
                return Ok(result);
            }
        }
    }

    // Fast path: serve getblock from block cache (then apply jq filter if needed)
    if method == "getblock" {
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
            let verbosity = params.get(1)
                .and_then(|v| v.as_u64())
                .unwrap_or(1) as u8;
            let chain_h = state.chain_height.load(std::sync::atomic::Ordering::Relaxed);
            let cached = state.block_cache.read().unwrap().get(hash, verbosity, chain_h);
            if let Some(json) = cached {
                // Apply jq filter if present, then return
                let filtered = match &query.filter {
                    Some(expr) if !expr.is_empty() => {
                        apply_jq(&json, expr)
                            .map_err(|e| (StatusCode::BAD_REQUEST, format!("jq filter error: {e}")))?
                    }
                    _ => json,
                };
                log_timing(start, &method);
                return Ok(Json(filtered));
            }
        }
    }

    // Call the node
    let result = state.rpc.proxy_call(&method, &params)
        .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;

    // Populate caches for getblockhash and getblock responses
    if method == "getblockhash" {
        if let (Some(height), Some(hash)) = (
            params.first().and_then(|v| v.as_u64()).map(|h| h as u32),
            result.as_str(),
        ) {
            state.hash_cache.write().await.insert(height, hash.to_string());
        }
    } else if method == "getblock" {
        if let (Some(height), Some(hash)) = (
            result.get("height").and_then(|v| v.as_u64()).map(|h| h as u32),
            result.get("hash").and_then(|v| v.as_str()),
        ) {
            state.hash_cache.write().await.insert(height, hash.to_string());

            // Also populate block cache
            let verbosity = params.get(1)
                .and_then(|v| v.as_u64())
                .unwrap_or(1) as u8;
            state.block_cache.write().unwrap().insert(hash, verbosity, &result);
        }
    }

    // Apply jq filter if present — shells out to system `jq` for full compatibility
    let filtered = match &query.filter {
        Some(expr) if !expr.is_empty() => {
            if expr.len() > 10_000 {
                return Err((StatusCode::BAD_REQUEST, "filter expression too long".into()));
            }
            apply_jq(&result, expr)
                .map_err(|e| (StatusCode::BAD_REQUEST, format!("jq filter error: {e}")))?
        }
        _ => result,
    };

    // Log timing + cache stats for getblock
    if method == "getblock" {
        let (hits, misses, cached) = state.block_cache.read().unwrap().stats();
        use std::io::Write;
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        let stderr = std::io::stderr();
        let mut w = stderr.lock();
        let total = hits + misses;
        if ms >= 1.0 {
            let _ = writeln!(w, "  [proxy {ms:.0}ms] {method} (cache: {hits}/{total} hits, {cached} blocks)");
        } else {
            let _ = writeln!(w, "  [proxy {ms:.2}ms] {method} (cache: {hits}/{total} hits, {cached} blocks)");
        }
    } else {
        log_timing(start, &method);
    }
    Ok(Json(filtered))
}

/// Write elapsed time directly to stderr — no allocation.
pub fn log_timing(start: std::time::Instant, label: &str) {
    use std::io::Write;
    let ms = start.elapsed().as_secs_f64() * 1000.0;
    let stderr = std::io::stderr();
    let mut w = stderr.lock();
    if ms >= 1000.0 {
        let _ = writeln!(w, "  [proxy {:.1}s] {label}", ms / 1000.0);
    } else if ms >= 1.0 {
        let _ = writeln!(w, "  [proxy {:.0}ms] {label}", ms);
    } else {
        let _ = writeln!(w, "  [proxy {:.2}ms] {label}", ms);
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
    cache.insert(expr.to_string(), compiled.clone());
    Ok(compiled)
}

/// Apply a jq filter expression to a JSON value using jaq (pure Rust).
///
/// Filter compilation is cached — first call compiles, subsequent calls reuse.
fn apply_jq(value: &Value, expr: &str) -> Result<Value, String> {
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
        let params = parse_params("42,3.14,true,hello");
        assert_eq!(params[0], json!(42));
        assert_eq!(params[1], json!(3.14));
        assert_eq!(params[2], json!(true));
        assert_eq!(params[3], json!("hello"));
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
}

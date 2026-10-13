/// JSON-RPC 1.0 client with Basic auth and connection pooling.
use serde_json::{json, Value};

pub struct RpcClient {
    url: String,
    auth: String,
    agent: ureq::Agent,
}

/// Largest RPC answer read (a batch of verbose transactions can be big).
const MAX_RESPONSE_BYTES: u64 = 256 * 1024 * 1024;

impl RpcClient {
    pub fn new(url: &str, user: &str, pass: &str) -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(std::time::Duration::from_secs(30)))
            .http_status_as_error(false)
            .max_idle_connections_per_host(4)
            .build()
            .into();
        Self {
            url: url.to_string(),
            auth: format!("Basic {}", base64_encode(&format!("{user}:{pass}"))),
            agent,
        }
    }

    /// POST a JSON-RPC body and return the decoded answer.
    fn post(&self, body: &Value) -> Result<Value, String> {
        let mut resp = self
            .agent
            .post(&self.url)
            .header("Authorization", &self.auth)
            .header("Content-Type", "application/json")
            .send(body.to_string())
            .map_err(|e| format!("connection error: {e}"))?;
        let status = resp.status();
        let text = resp
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_to_string()
            .map_err(|e| format!("read error: {e}"))?;
        match serde_json::from_str::<Value>(&text) {
            Ok(json) => Ok(json),
            Err(_) if !status.is_success() => Err(format!("HTTP {}: {text}", status.as_u16())),
            Err(e) => Err(format!("JSON parse error: {e}")),
        }
    }

    /// The `result` of one JSON-RPC answer, or its error message.
    fn result_of(json: &Value) -> Result<Value, String> {
        if let Some(err) = json.get("error").filter(|e| !e.is_null()) {
            let msg = err.get("message").and_then(|m| m.as_str()).unwrap_or("unknown RPC error");
            return Err(msg.to_string());
        }
        Ok(json.get("result").cloned().unwrap_or(Value::Null))
    }

    /// Send a JSON-RPC 1.0 request and return the "result" field.
    fn call(&self, method: &str, params: &[Value]) -> Result<Value, String> {
        let body = json!({
            "jsonrpc": "1.0",
            "id": "pivx-bridge",
            "method": method,
            "params": params,
        });
        Self::result_of(&self.post(&body)?)
    }

    /// Several calls of `method` in one JSON-RPC batch request. Answers
    /// come back in the order of `params`.
    pub fn batch(&self, method: &str, params: &[Vec<Value>]) -> Result<Vec<Result<Value, String>>, String> {
        if params.is_empty() {
            return Ok(Vec::new());
        }
        let body = Value::Array(
            params
                .iter()
                .enumerate()
                .map(|(i, p)| json!({ "jsonrpc": "1.0", "id": i, "method": method, "params": p }))
                .collect(),
        );
        let answer = self.post(&body)?;
        let Value::Array(items) = answer else {
            // A node error for the whole batch comes back as one object.
            return Err(Self::result_of(&answer).err().unwrap_or_else(|| "batch: unexpected answer".into()));
        };
        let mut out: Vec<Result<Value, String>> = vec![Err("missing batch answer".into()); params.len()];
        for item in items {
            if let Some(i) = item.get("id").and_then(|v| v.as_u64()).map(|v| v as usize) {
                if i < out.len() {
                    out[i] = Self::result_of(&item);
                }
            }
        }
        Ok(out)
    }

    // -- Convenience methods --

    pub fn get_block_count(&self) -> Result<u64, String> {
        self.call("getblockcount", &[])?
            .as_u64()
            .ok_or_else(|| "getblockcount: not a number".into())
    }

    pub fn get_block_hash(&self, height: u32) -> Result<String, String> {
        self.call("getblockhash", &[json!(height)])?
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| "getblockhash: not a string".into())
    }

    pub fn get_block(&self, hash: &str, verbosity: u32) -> Result<Value, String> {
        self.call("getblock", &[json!(hash), json!(verbosity)])
    }

    pub fn get_raw_transaction(&self, txid: &str, verbose: bool) -> Result<Value, String> {
        self.call("getrawtransaction", &[json!(txid), json!(verbose)])
    }

    pub fn send_raw_transaction(&self, hex: &str) -> Result<String, String> {
        self.call("sendrawtransaction", &[json!(hex)])?
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| "sendrawtransaction: unexpected response".into())
    }

    /// Generic RPC call for the proxy endpoint.
    pub fn proxy_call(&self, method: &str, params: &[Value]) -> Result<Value, String> {
        self.call(method, params)
    }
}

/// Minimal base64 encoder (no external crate needed for this).
fn base64_encode(input: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(triple >> 18 & 0x3F) as usize] as char);
        out.push(ALPHABET[(triple >> 12 & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(triple >> 6 & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

//! Blockbook-compatible `/api/v2/*` endpoints (the subset light
//! wallets use). Amounts are satoshi strings, as in Blockbook.
//!
//!   GET  /api/v2/api
//!   GET  /api/v2/address/{address}?page&pageSize&from&to&details
//!   GET  /api/v2/xpub/{xpub}?page&pageSize&from&to&details&tokens&gap
//!   GET  /api/v2/utxo/{address|xpub}?confirmed&gap
//!   GET  /api/v2/tx/{txid}
//!   GET  /api/v2/block-index/{height}
//!   GET  /api/v2/sendtx/{hex}   POST /api/v2/sendtx/  (body = hex)
//!   POST /api/v2/watch          (long-poll, bridge extension)
use std::collections::HashSet;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{json, Value};

use super::store::{addr_hash, txid_from_hex, txid_to_hex, value_to_sats, Txid, FLAG_COINBASE, FLAG_COINSTAKE};
use super::xpub::{is_xpub, ExtendedPubKey};
use super::AddrIndex;

const DEFAULT_PAGE_SIZE: usize = 1000;
const MAX_PAGE_SIZE: usize = 1000;
const DEFAULT_GAP: u32 = 20;
const MAX_GAP: u32 = 1000;

pub fn routes(idx: Arc<AddrIndex>) -> Router {
    Router::new()
        .route("/api", get(status))
        .route("/api/v2", get(status))
        .route("/api/v2/api", get(status))
        .route("/api/v2/address/{address}", get(address))
        .route("/api/v2/xpub/{xpub}", get(xpub))
        .route("/api/v2/utxo/{desc}", get(utxo))
        .route("/api/v2/tx/{txid}", get(tx))
        .route("/api/v2/block-index/{height}", get(block_index))
        .route("/api/v2/sendtx/{hex}", get(send_tx_get))
        .route("/api/v2/sendtx/", post(send_tx_post))
        .route("/api/v2/sendtx", post(send_tx_post))
        .route("/api/v2/watch", post(watch))
        .with_state(idx)
}

type ApiResult = Result<Json<Value>, ApiError>;

pub struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

fn bad(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, msg.into())
}

fn internal(msg: impl Into<String>) -> ApiError {
    ApiError(StatusCode::INTERNAL_SERVER_ERROR, msg.into())
}

async fn blocking<F>(f: F) -> ApiResult
where
    F: FnOnce() -> ApiResult + Send + 'static,
{
    tokio::task::spawn_blocking(f).await.map_err(|e| internal(e.to_string()))?
}

#[derive(Deserialize, Default, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ListQuery {
    page: Option<usize>,
    page_size: Option<usize>,
    from: Option<u32>,
    to: Option<u32>,
    details: Option<String>,
    tokens: Option<String>,
    gap: Option<u32>,
    confirmed: Option<bool>,
}

#[derive(PartialEq, PartialOrd, Clone, Copy)]
enum Details {
    Basic,
    Tokens,
    TokenBalances,
    Txids,
    Txs,
}

impl Details {
    fn parse(s: Option<&str>) -> Self {
        match s.unwrap_or("txids") {
            "basic" => Self::Basic,
            "tokens" => Self::Tokens,
            "tokenBalances" => Self::TokenBalances,
            "txs" => Self::Txs,
            _ => Self::Txids,
        }
    }
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

async fn status(State(idx): State<Arc<AddrIndex>>) -> ApiResult {
    blocking(move || {
        let tip = idx.indexed_tip();
        let (best_hash, best_time) = tip
            .and_then(|t| idx.store.block_info(t).ok().flatten())
            .unwrap_or_default();
        let mempool_size = idx.mempool.read().unwrap().len();
        let (txs, outputs, addresses) = idx.store.counts().unwrap_or_default();
        Ok(Json(json!({
            "blockbook": {
                "coin": "PIVX",
                "host": "pivx-bridge",
                "version": env!("CARGO_PKG_VERSION"),
                "bestHeight": tip.unwrap_or(0),
                "lastBlockTime": best_time,
                "inSync": idx.in_sync.load(Ordering::Relaxed),
                "inSyncMempool": idx.in_sync.load(Ordering::Relaxed),
                "mempoolSize": mempool_size,
                "decimals": 8,
                "about": "pivx-bridge transparent address index (Blockbook API v2 subset)",
                "indexedTxs": txs,
                "indexedOutputs": outputs,
                "indexedAddresses": addresses,
            },
            "backend": {
                "chain": idx.net.chain,
                "blocks": tip.unwrap_or(0),
                "bestBlockHash": best_hash,
                "nodeBlocks": idx.node_tip.load(Ordering::Relaxed),
            }
        })))
    })
    .await
}

async fn block_index(State(idx): State<Arc<AddrIndex>>, Path(height): Path<u32>) -> ApiResult {
    blocking(move || match idx.store.block_info(height).map_err(internal)? {
        Some((hash, _)) => Ok(Json(json!({ "blockHash": hash }))),
        None => Err(ApiError(StatusCode::NOT_FOUND, "block not found".into())),
    })
    .await
}

// ---------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------

impl AddrIndex {
    /// Verbose tx JSON from the node (cached for confirmed txs).
    fn raw_tx(&self, txid: &Txid, confirmed: bool) -> Result<Value, String> {
        if let Some(v) = self.tx_cache.lock().unwrap().get(txid) {
            return Ok(v);
        }
        let v = self.rpc.get_raw_transaction(&txid_to_hex(txid), true)?;
        if confirmed {
            self.tx_cache.lock().unwrap().put(*txid, v.clone());
        }
        Ok(v)
    }

    /// Blockbook-style transaction object.
    pub fn tx_json(&self, txid: &Txid) -> Result<Value, String> {
        let location = self.store.tx_location(txid)?;
        let mempool_seen = self.mempool.read().unwrap().txs.get(txid).map(|t| t.first_seen);
        let raw = self.raw_tx(txid, location.is_some())?;
        let tip = self.indexed_tip().unwrap_or(0);

        let mut value_in: u64 = 0;
        let mut vin_json = Vec::new();
        let mut is_coinbase = false;
        for (i, input) in raw["vin"].as_array().cloned().unwrap_or_default().iter().enumerate() {
            if let Some(cb) = input.get("coinbase").and_then(|c| c.as_str()) {
                is_coinbase = true;
                vin_json.push(json!({ "n": i, "coinbase": cb, "isAddress": false, "value": "0" }));
                continue;
            }
            let prev = input["txid"].as_str().unwrap_or_default();
            let n = input["vout"].as_u64().unwrap_or(0) as u32;
            let mut entry = json!({
                "txid": prev,
                "vout": n,
                "sequence": input["sequence"],
                "n": i,
                "isAddress": false,
            });
            let resolved = txid_from_hex(prev).and_then(|p| {
                self.store.output(&p, n).ok().flatten().map(|o| (o.value, o.addresses)).or_else(|| {
                    let mp = self.mempool.read().unwrap();
                    mp.txs.get(&p).and_then(|t| t.outputs.iter().find(|o| o.n == n)).map(|o| (o.value, o.addresses.clone()))
                })
            });
            if let Some((value, addresses)) = resolved {
                value_in += value;
                entry["value"] = json!(value.to_string());
                entry["isAddress"] = json!(!addresses.is_empty());
                entry["addresses"] = json!(addresses);
            }
            vin_json.push(entry);
        }

        let mut value_out: u64 = 0;
        let mut vout_json = Vec::new();
        let outs = raw["vout"].as_array().cloned().unwrap_or_default();
        let is_coinstake = !is_coinbase
            && outs.len() >= 2
            && value_to_sats(&outs[0]["value"]) == 0
            && outs[0]["scriptPubKey"]["hex"].as_str().unwrap_or("x").is_empty();
        for (i, out) in outs.iter().enumerate() {
            let n = out["n"].as_u64().unwrap_or(i as u64) as u32;
            let value = value_to_sats(&out["value"]);
            value_out += value;
            let addresses = super::store::vout_addresses(out);
            let mut entry = json!({
                "value": value.to_string(),
                "n": n,
                "hex": out["scriptPubKey"]["hex"],
                "type": out["scriptPubKey"]["type"],
                "isAddress": !addresses.is_empty(),
                "addresses": addresses,
            });
            if let Some(a) = addresses.first() {
                let spent_confirmed = location.is_some() && !self.store.is_unspent(txid, n, a).unwrap_or(true);
                let spent_mempool = self.mempool.read().unwrap().is_spent(txid, n);
                if spent_confirmed || spent_mempool {
                    entry["spent"] = json!(true);
                }
            }
            vout_json.push(entry);
        }

        let value_balance: i64 = raw["valueBalanceSat"].as_i64().unwrap_or(0);
        let fees: i64 = if is_coinbase || is_coinstake {
            0
        } else {
            (value_in as i64 + value_balance - value_out as i64).max(0)
        };

        let (block_height, block_hash, block_time, confirmations): (i64, Value, u64, u32) = match location {
            Some((h, _)) => {
                let (hash, time) = self.store.block_info(h)?.unwrap_or_default();
                (h as i64, json!(hash), time as u64, tip.saturating_sub(h) + 1)
            }
            None => (-1, Value::Null, mempool_seen.unwrap_or(0), 0),
        };

        let mut j = json!({
            "txid": txid_to_hex(txid),
            "version": raw["version"],
            "type": raw["type"],
            "vin": vin_json,
            "vout": vout_json,
            "blockHeight": block_height,
            "confirmations": confirmations,
            "blockTime": block_time,
            "value": value_out.to_string(),
            "valueIn": value_in.to_string(),
            "fees": fees.to_string(),
            "hex": raw["hex"],
            "coinbase": is_coinbase,
            "coinstake": is_coinstake,
        });
        if !block_hash.is_null() {
            j["blockHash"] = block_hash;
        }
        if raw.get("valueBalanceSat").is_some() {
            j["valueBalanceSat"] = json!(value_balance.to_string());
            j["shieldSpends"] = json!(raw["vShieldSpend"].as_array().map(|a| a.len()).unwrap_or(0));
            j["shieldOutputs"] = json!(raw["vShieldOutput"].as_array().map(|a| a.len()).unwrap_or(0));
        }
        Ok(j)
    }
}

async fn tx(State(idx): State<Arc<AddrIndex>>, Path(txid): Path<String>) -> ApiResult {
    blocking(move || {
        let t = txid_from_hex(&txid).ok_or_else(|| bad("invalid txid"))?;
        idx.tx_json(&t).map(Json).map_err(|e| ApiError(StatusCode::NOT_FOUND, e))
    })
    .await
}

// ---------------------------------------------------------------------------
// Address / xpub history
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct DerivedAddr {
    address: String,
    path: String,
    used: bool,
}

impl AddrIndex {
    fn derived(&self, xpub: &str, chain: u32, index: u32) -> Result<String, String> {
        {
            let cache = self.xpub_cache.lock().unwrap();
            if let Some(chains) = cache.get(xpub) {
                if let Some(a) = chains[chain as usize].get(index as usize) {
                    return Ok(a.clone());
                }
            }
        }
        let key = ExtendedPubKey::parse(xpub)?;
        let chain_key = key.derive_child(chain)?;
        let mut cache = self.xpub_cache.lock().unwrap();
        if cache.len() > 1_000 {
            cache.clear();
        }
        let entry = cache.entry(xpub.to_string()).or_insert_with(|| [Vec::new(), Vec::new()]);
        let list = &mut entry[chain as usize];
        // Derive in chunks so gap scans don't re-parse the xpub per address.
        let target = (index as usize + 1).max(list.len() + 50);
        while list.len() < target {
            let child = chain_key.derive_child(list.len() as u32)?;
            list.push(child.p2pkh_address(self.net.p2pkh_prefix));
        }
        Ok(list[index as usize].clone())
    }

    /// Walk receive (0) and change (1) chains until `gap` consecutive
    /// unused addresses, like Blockbook. Returns used + gap addresses.
    fn xpub_addresses(&self, xpub: &str, gap: u32) -> Result<Vec<DerivedAddr>, String> {
        let key = ExtendedPubKey::parse(xpub)?;
        let account = key.child_number & 0x7fff_ffff;
        let coin = self.net.bip44_coin_type;
        let mp = self.mempool.read().unwrap();
        let mut out = Vec::new();
        for chain in 0..2u32 {
            let mut unused_run = 0;
            let mut i = 0u32;
            while unused_run < gap {
                let address = self.derived(xpub, chain, i)?;
                let used = self.store.is_used(&address)? || mp.touches(&address);
                unused_run = if used { 0 } else { unused_run + 1 };
                out.push(DerivedAddr { address, path: format!("m/44'/{coin}'/{account}'/{chain}/{i}"), used });
                i += 1;
            }
        }
        Ok(out)
    }

    /// Ordered (newest first) unique txids touching `addrs`, mempool first.
    fn collect_txids(&self, addrs: &[&str], from: u32, to: Option<u32>) -> Result<Vec<Txid>, String> {
        let mut seen: HashSet<Txid> = HashSet::new();
        let mut mempool: Vec<(u64, Txid)> = Vec::new();
        if to.is_none() {
            let mp = self.mempool.read().unwrap();
            for a in addrs {
                for t in mp.txids_for(a) {
                    if seen.insert(t) {
                        mempool.push((mp.txs.get(&t).map(|x| x.first_seen).unwrap_or(0), t));
                    }
                }
            }
        }
        mempool.sort_by_key(|m| std::cmp::Reverse(m.0));
        let mut confirmed: Vec<(u32, u32, Txid)> = Vec::new();
        for a in addrs {
            for h in self.store.history(a, from, to.unwrap_or(u32::MAX))? {
                if seen.insert(h.txid) {
                    confirmed.push((h.height, h.txpos, h.txid));
                }
            }
        }
        confirmed.sort_by_key(|c| std::cmp::Reverse((c.0, c.1)));
        Ok(mempool.into_iter().map(|(_, t)| t).chain(confirmed.into_iter().map(|(_, _, t)| t)).collect())
    }

    /// (balance, totalReceived, totalSent, txs, unconfirmedBalance, unconfirmedTxs) for one address.
    fn balances(&self, addr: &str) -> Result<(u64, u64, u64, u32, i64, u32), String> {
        let s = self.store.stats(addr)?;
        let mp = self.mempool.read().unwrap();
        let ah = super::store::addr_hash(addr);
        let mut unconf: i64 = 0;
        let mut unconf_txs = 0;
        for t in mp.txids_for(addr) {
            if let Some(tx) = mp.txs.get(&t) {
                if let Some((r, s)) = tx.deltas.get(&ah) {
                    unconf += *r as i64 - *s as i64;
                    unconf_txs += 1;
                }
            }
        }
        Ok((s.received.saturating_sub(s.sent), s.received, s.sent, s.txs, unconf, unconf_txs))
    }
}

fn paginate(total: usize, q: &ListQuery) -> (usize, usize, usize, usize) {
    let size = q.page_size.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);
    let total_pages = total.div_ceil(size);
    // Blockbook returns the last page for an out-of-range page number;
    // MPW's getNumPages relies on that.
    let page = q.page.unwrap_or(1).clamp(1, total_pages.max(1));
    let start = ((page - 1) * size).min(total);
    let end = (start + size).min(total);
    (page, total_pages, start, end)
}

fn history_json(idx: &AddrIndex, txids: &[Txid], q: &ListQuery, details: Details) -> Result<Value, String> {
    let (page, total_pages, start, end) = paginate(txids.len(), q);
    let mut j = json!({
        "page": page,
        "totalPages": total_pages,
        "itemsOnPage": q.page_size.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE),
        "txs": txids.len(),
    });
    let slice = &txids[start..end];
    if details == Details::Txids && !slice.is_empty() {
        j["txids"] = json!(slice.iter().map(txid_to_hex).collect::<Vec<_>>());
    }
    if details == Details::Txs && !slice.is_empty() {
        let mut list = Vec::with_capacity(slice.len());
        for t in slice {
            list.push(idx.tx_json(t)?);
        }
        j["transactions"] = json!(list);
    }
    Ok(j)
}

async fn address(
    State(idx): State<Arc<AddrIndex>>,
    Path(addr): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult {
    blocking(move || {
        if is_xpub(&addr) {
            return Err(bad("use /api/v2/xpub for extended keys"));
        }
        let details = Details::parse(q.details.as_deref());
        let (bal, recv, sent, _txs, unconf, unconf_txs) = idx.balances(&addr).map_err(internal)?;
        let txids = if details >= Details::Txids {
            idx.collect_txids(&[addr.as_str()], q.from.unwrap_or(0), q.to).map_err(internal)?
        } else {
            Vec::new()
        };
        let mut j = history_json(&idx, &txids, &q, details).map_err(internal)?;
        if details < Details::Txids {
            j["txs"] = json!(idx.store.stats(&addr).map_err(internal)?.txs + unconf_txs);
        }
        j["address"] = json!(addr);
        j["balance"] = json!(bal.to_string());
        j["totalReceived"] = json!(recv.to_string());
        j["totalSent"] = json!(sent.to_string());
        j["unconfirmedBalance"] = json!(unconf.to_string());
        j["unconfirmedTxs"] = json!(unconf_txs);
        Ok(Json(j))
    })
    .await
}

async fn xpub(
    State(idx): State<Arc<AddrIndex>>,
    Path(xpub): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult {
    blocking(move || {
        let details = Details::parse(q.details.as_deref());
        let gap = q.gap.unwrap_or(DEFAULT_GAP).clamp(1, MAX_GAP);
        let addrs = idx.xpub_addresses(&xpub, gap).map_err(bad)?;
        let used: Vec<&DerivedAddr> = addrs.iter().filter(|a| a.used).collect();

        let (mut bal, mut recv, mut sent, mut unconf, mut unconf_txs) = (0u64, 0u64, 0u64, 0i64, 0u32);
        let mut tokens = Vec::new();
        let token_filter = q.tokens.as_deref().unwrap_or("nonzero");
        for a in &addrs {
            let (b, r, s, txs, u, ut) = if a.used { idx.balances(&a.address).map_err(internal)? } else { (0, 0, 0, 0, 0, 0) };
            bal += b;
            recv += r;
            sent += s;
            unconf += u;
            unconf_txs += ut;
            let include = match token_filter {
                "derived" => true,
                "used" => a.used,
                _ => b > 0 || u != 0,
            };
            if details >= Details::Tokens && include {
                let mut t = json!({
                    "type": "XPUBAddress",
                    "name": a.address,
                    "path": a.path,
                    "transfers": txs + ut,
                    "decimals": 8,
                });
                if details >= Details::TokenBalances {
                    t["balance"] = json!(b.to_string());
                    t["totalReceived"] = json!(r.to_string());
                    t["totalSent"] = json!(s.to_string());
                }
                tokens.push(t);
            }
        }

        let addr_refs: Vec<&str> = used.iter().map(|a| a.address.as_str()).collect();
        let txids = idx.collect_txids(&addr_refs, q.from.unwrap_or(0), q.to).map_err(internal)?;
        let mut j = history_json(&idx, &txids, &q, details).map_err(internal)?;
        j["address"] = json!(xpub);
        j["balance"] = json!(bal.to_string());
        j["totalReceived"] = json!(recv.to_string());
        j["totalSent"] = json!(sent.to_string());
        j["unconfirmedBalance"] = json!(unconf.to_string());
        j["unconfirmedTxs"] = json!(unconf_txs);
        j["usedTokens"] = json!(used.len());
        if details >= Details::Tokens && !tokens.is_empty() {
            j["tokens"] = json!(tokens);
        }
        Ok(Json(j))
    })
    .await
}

// ---------------------------------------------------------------------------
// UTXO
// ---------------------------------------------------------------------------

async fn utxo(
    State(idx): State<Arc<AddrIndex>>,
    Path(desc): Path<String>,
    Query(q): Query<ListQuery>,
) -> ApiResult {
    blocking(move || {
        let targets: Vec<(String, Option<String>)> = if is_xpub(&desc) {
            let gap = q.gap.unwrap_or(DEFAULT_GAP).clamp(1, MAX_GAP);
            idx.xpub_addresses(&desc, gap)
                .map_err(bad)?
                .into_iter()
                .filter(|a| a.used)
                .map(|a| (a.address, Some(a.path)))
                .collect()
        } else {
            vec![(desc.clone(), None)]
        };
        let tip = idx.indexed_tip().unwrap_or(0);
        let only_confirmed = q.confirmed.unwrap_or(false);
        let mp = idx.mempool.read().unwrap();
        let mut seen: HashSet<(Txid, u32)> = HashSet::new();
        let mut out = Vec::new();
        for (addr, path) in &targets {
            if !only_confirmed {
                for t in mp.txids_for(addr) {
                    let Some(tx) = mp.txs.get(&t) else { continue };
                    for o in &tx.outputs {
                        if o.addresses.iter().any(|a| a == addr) && !mp.is_spent(&t, o.n) && seen.insert((t, o.n)) {
                            let mut u = json!({
                                "txid": txid_to_hex(&t),
                                "vout": o.n,
                                "value": o.value.to_string(),
                                "confirmations": 0,
                                "address": addr,
                            });
                            if let Some(p) = path {
                                u["path"] = json!(p);
                            }
                            out.push(u);
                        }
                    }
                }
            }
            for u in idx.store.utxos(addr).map_err(internal)? {
                if mp.is_spent(&u.txid, u.vout) || !seen.insert((u.txid, u.vout)) {
                    continue;
                }
                let mut j = json!({
                    "txid": txid_to_hex(&u.txid),
                    "vout": u.vout,
                    "value": u.value.to_string(),
                    "height": u.height,
                    "confirmations": tip.saturating_sub(u.height) + 1,
                    "address": addr,
                });
                if u.flags & FLAG_COINBASE != 0 {
                    j["coinbase"] = json!(true);
                }
                if u.flags & FLAG_COINSTAKE != 0 {
                    j["coinstake"] = json!(true);
                }
                if let Some(p) = path {
                    j["path"] = json!(p);
                }
                out.push(j);
            }
        }
        Ok(Json(json!(out)))
    })
    .await
}

// ---------------------------------------------------------------------------
// Broadcast
// ---------------------------------------------------------------------------

fn broadcast(idx: &AddrIndex, hex: &str) -> ApiResult {
    let hex = hex.trim();
    if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(bad("invalid transaction hex"));
    }
    idx.rpc
        .send_raw_transaction(hex)
        .map(|txid| Json(json!({ "result": txid })))
        .map_err(bad)
}

async fn send_tx_get(State(idx): State<Arc<AddrIndex>>, Path(hex): Path<String>) -> ApiResult {
    blocking(move || broadcast(&idx, &hex)).await
}

async fn send_tx_post(State(idx): State<Arc<AddrIndex>>, body: String) -> ApiResult {
    blocking(move || broadcast(&idx, &body)).await
}

// ---------------------------------------------------------------------------
// Long-poll (bridge extension, not part of Blockbook)
// ---------------------------------------------------------------------------

const WATCH_DEFAULT_SECS: u64 = 25;
const WATCH_MAX_SECS: u64 = 120;
const WATCH_MAX_ADDRESSES: usize = 10_000;

#[derive(Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct WatchRequest {
    /// Tip the client knows; any other tip answers at once.
    height: Option<u32>,
    hash: Option<String>,
    /// `mempoolSeq` from the previous answer; omit on the first call.
    mempool_seq: Option<u64>,
    /// Addresses whose new mempool txs should wake the client.
    #[serde(default)]
    addresses: Vec<String>,
    timeout: Option<u64>,
}

/// `POST /api/v2/watch` — answers as soon as a block is indexed or a
/// mempool tx touching one of `addresses` arrives, else after `timeout`
/// seconds. Response: `{height, hash, mempoolSeq, newBlock, txids,
/// reset, changed}`. `reset` means the client's `mempoolSeq` is unknown
/// here (bridge restarted or client too far behind): refresh fully.
async fn watch(State(idx): State<Arc<AddrIndex>>, body: Option<Json<WatchRequest>>) -> ApiResult {
    let req = body.map(|b| b.0).unwrap_or_default();
    if req.addresses.len() > WATCH_MAX_ADDRESSES {
        return Err(bad(format!("too many addresses (max {WATCH_MAX_ADDRESSES})")));
    }
    let addrs: HashSet<_> = req.addresses.iter().map(|a| addr_hash(a)).collect();
    let secs = req.timeout.unwrap_or(WATCH_DEFAULT_SECS).clamp(1, WATCH_MAX_SECS);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(secs);
    let mut rx = idx.changes.subscribe();
    let mut since = req.mempool_seq;
    loop {
        let state = rx.borrow_and_update().clone();
        let new_block = req.height.is_some_and(|h| h != state.height)
            || req.hash.as_deref().is_some_and(|h| h != state.hash);
        let (seq, txids) = match since {
            None => (idx.mempool.read().unwrap().seq(), Some(vec![])),
            Some(s) => idx.mempool.read().unwrap().events_since(s, &addrs),
        };
        let reset = txids.is_none();
        let txids = txids.unwrap_or_default();
        let changed = new_block || reset || !txids.is_empty();
        let timed_out = !changed
            && !matches!(tokio::time::timeout_at(deadline, rx.changed()).await, Ok(Ok(())));
        if changed || timed_out {
            return Ok(Json(json!({
                "height": state.height,
                "hash": state.hash,
                "mempoolSeq": seq,
                "newBlock": new_block,
                "txids": txids.iter().map(txid_to_hex).collect::<Vec<_>>(),
                "reset": reset,
                "changed": changed,
            })));
        }
        since = Some(seq);
    }
}

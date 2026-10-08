<p align="center">
  <strong>PIVX Bridge</strong><br>
  <em>High-performance shield sync server for the PIVX network.</em><br>
  <em>Drop-in replacement for PivxNodeController, written in Rust.</em>
</p>

---

A shield sync bridge that connects to a PIVX full node, scans for Sapling shielded transactions, and serves compact shield data to light wallets over HTTP. Fully compatible with [MyPIVXWallet](https://github.com/PIVX-Labs/MyPIVXWallet) — zero client changes required.

## Performance

Benchmarked head-to-head against PivxNodeController on the same production server:

| Benchmark | PNC | Bridge | Improvement |
|-----------|-----|--------|-------------|
| getblockcount | 4.2ms | 2.0ms | **2x** |
| getshieldblocks (34k JSON) | 11.2ms | 3.8ms | **3x** |
| getshielddata full (200MB) | 2.12s | 0.75s | **2.8x** |
| **getshielddata incremental** | **499ms** | **1.0ms** | **494x** |
| New block visibility | 60s (polling) | Instant (ZMQ) | **~** |
| RSS memory | 386MB | 210MB | **46% less** |
| VSZ memory | 1.9GB | 627MB | **67% less** |

### How

- **In-memory shield buffer** — the entire shield dataset (~200MB) is held in RAM. Requests serve a memory slice directly — zero disk I/O, zero file handle contention
- **Binary search indexing** — block lookups in O(log n) instead of linear scan. 17 comparisons for 34,000 shield blocks
- **Inline tx extraction** — `getblock` verbosity 2 returns tx hex inline, eliminating a separate RPC call per transaction. 100x fewer RPC calls during chain scan
- **ZMQ + polling** — new blocks indexed instantly via ZMQ hashblock notifications, with a 10s polling safety net that catches anything ZMQ misses
- **Block hash LRU cache** — the last 1,000 height→hash mappings are cached in memory. `getblockhash` proxy calls serve from cache in <0.01ms instead of ~1ms RPC round-trips. On production traffic, ~50% of proxy calls are cache hits
- **Opt-in compact formats** — strip Groth16 proofs and signatures that light wallets never verify, cutting sync data by 24-42%

## Quick Start

```bash
# Build
cargo build --release

# Run (with a PIVX node on localhost)
./target/release/pivx-bridge \
  --rpc-url http://127.0.0.1:51473 \
  --rpc-user rpc \
  --rpc-pass rpc
```

Or use a `.env` file (copy `.env.sample`):

```bash
cp .env.sample .env
# Edit .env with your node credentials
./target/release/pivx-bridge
```

The bridge scans from Sapling activation (block 2,700,501) on first run, then indexes new blocks in real-time via ZMQ.

## PIVX Node Configuration

Add to `pivx.conf`:

```
server=1
rpcuser=rpc
rpcpassword=rpc
zmqpubhashblock=tcp://127.0.0.1:28332
```

## API

All endpoints are served at both `/mainnet/...` and `/...` (without prefix).

### Shield Sync

| Route | Method | Description |
|-------|--------|-------------|
| `/mainnet/getshielddata?startBlock=N` | GET | Binary shield stream |
| `/mainnet/getshielddatalength?startBlock=N&endBlock=M` | GET | Byte count (for progress bars) |
| `/mainnet/getshieldblocks` | GET | JSON array of shield block heights |
| `/mainnet/sendrawtransaction` | POST | Broadcast raw transaction hex |
| `/mainnet/address_index` | GET | SQLite address index (for MPW-Tauri) |
| `/mainnet/sapling-output.params`, `/mainnet/sapling-spend.params` | GET | Sapling proving parameters for wallets that build shield transactions (served when found, see `SAPLING_PARAMS_DIR`) |

### RPC Proxy

| Route | Method | Description |
|-------|--------|-------------|
| `/mainnet/:method?params=a,b,c&filter=<jq>` | GET | Proxied RPC call with optional jq filtering |

The proxy validates methods against a configurable whitelist. Parameters are automatically type-coerced (numbers, booleans, strings). The `filter` parameter uses the system `jq` binary for full compatibility.

### Transparent Address Index (opt-in, `ADDR_INDEX=true`)

A Blockbook-compatible subset of `/api/v2`, so light wallets get transparent history, balances and UTXOs from the bridge instead of a separate Blockbook. MyPIVXWallet's `ExplorerNetwork` works against it unchanged.

| Route | Method | Description |
|-------|--------|-------------|
| `/mainnet/api/v2/api` | GET | Index status (`blockbook.inSync`, `backend.blocks`, `bestBlockHash`) |
| `/mainnet/api/v2/address/{address}` | GET | Address balance + history (`page`, `pageSize`, `from`, `to`, `details=basic\|txids\|txs`) |
| `/mainnet/api/v2/xpub/{xpub}` | GET | BIP44 account xpub, gap-limit walk of chains 0/1 (`gap`, `tokens=nonzero\|used\|derived`, `details=…\|tokens\|tokenBalances`) |
| `/mainnet/api/v2/utxo/{address\|xpub}` | GET | Unspent outputs incl. mempool (`confirmed=true` to exclude); coinbase/coinstake outputs are flagged |
| `/mainnet/api/v2/tx/{txid}` | GET | Transaction with resolved input addresses/values, `hex`, fees, shield value balance |
| `/mainnet/api/v2/block-index/{height}` | GET | Block hash at height |
| `/mainnet/api/v2/sendtx/` | POST / GET `{hex}` | Broadcast |
| `/mainnet/api/v2/watch` | POST | Long-poll for changes (bridge extension, see below) |

Every address the node decodes is indexed — P2PKH, P2SH, P2PK, exchange (`EXM…`) and both the staker and owner of cold-stake (P2CS) outputs. Unconfirmed transactions are tracked from the node's mempool. Reorgs are rolled back exactly (block hashes and undo data for the last 1000 blocks are kept).

`/api/v2/watch` lets wallets react within ~2 s instead of polling. POST a JSON body `{"height", "hash"?, "mempoolSeq"?, "addresses": [...], "timeout"?}`; the bridge answers as soon as a block other than `height`/`hash` is indexed or a mempool tx touching one of `addresses` arrives after `mempoolSeq`, otherwise after `timeout` seconds (default 25, max 120). The answer is `{height, hash, mempoolSeq, newBlock, txids, reset, changed}`; send its `height`, `hash` and `mempoolSeq` with the next call. `reset: true` means the bridge does not know the client's `mempoolSeq` (it restarted, or the client fell more than 10 000 mempool arrivals behind) and the client should do a full refresh. Omit `mempoolSeq` on the first call.

The index lives in its own `addr_index.redb` (redb, pure Rust), is built by its own thread and never touches the shield stream. The first run indexes the whole chain from genesis; status is visible at `/api/v2/api`. The node needs `txindex=1` (PIVX's default) for transaction details.

### Stream Formats

The `getshielddata` endpoint accepts an optional `format` query parameter:

| Format | Packet | Per output | Use case |
|--------|--------|-----------|----------|
| `pivx` (default) | 0x03 full raw tx | 948 bytes | MPW compatibility |
| `compact` | 0x04 | 724 bytes (-24%) | Wallets with sender recovery |
| `compactplus` | 0x05 | 644 bytes (-32%) | New wallet bootstrap |

The default PIVX format is byte-identical to PivxNodeController output.

## Binary Protocol

The shield stream is a sequence of length-prefixed packets:

```
PivxNodeController-compatible (default):

  Transaction:   [4-byte LE length][raw PIVX v3 tx bytes]
  Block footer:  [4-byte LE length=9][0x5d][height:4LE][time:4LE]

  Transactions come first, block footer comes last (per block).

Compact (opt-in):

  Block header:  [4-byte LE length=5][0x5d][height:4LE]
  Compact tx:    [4-byte LE length][0x04][nSpends:1][nOutputs:1]
                   per spend: nullifier(32)
                   per output: cmu(32) + epk(32) + enc(580) + out_ct(80)

CompactPlus (opt-in):

  Same as compact, but type=0x05 and out_ciphertext omitted per output.
```

## Architecture

```
src/
  main.rs       Startup, initial scan, ZMQ + polling subscribers, axum server
  config.rs     CLI args + .env configuration
  rpc.rs        JSON-RPC 1.0 client with auth + connection pooling + 30s timeout
  scanner.rs    Block scanner + PIVX v3 Sapling tx parser (validated against PIVX Core)
  stream.rs     Binary stream encoder (PivxCompat / Compact / CompactPlus)
  cache.rs      Persistent shield.bin cache with crash recovery
  index.rs      Binary search index with byte offsets (shield.json compat)
  api.rs        HTTP endpoints with in-memory buffer serving + block hash LRU cache
  proxy.rs      RPC proxy with system jq filtering + response timing
  addr_index/   Transparent address index (opt-in)
    store.rs    redb tables: outputs, per-address history/UTXOs/stats, undo
    mod.rs      Indexer thread: parallel catch-up, reorg rollback, mempool
    xpub.rs     BIP32 public derivation + P2PKH encoding for xpub queries
    api.rs      Blockbook-compatible /api/v2 endpoints
```

## Configuration

All options support both CLI flags and environment variables:

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--rpc-url` | `RPC_URL` | `http://127.0.0.1:51473` | PIVX node RPC endpoint |
| `--rpc-user` | `RPC_USER` | `rpc` | RPC username |
| `--rpc-pass` | `RPC_PASS` | `rpc` | RPC password |
| `--zmq-url` | `ZMQ_URL` | `tcp://127.0.0.1:28332` | ZMQ hashblock endpoint |
| `--port` | `PORT` | `3000` | HTTP server port |
| `--sapling-height` | `SAPLING_HEIGHT` | `2700501` | Sapling activation block |
| `--no-compression` | `NO_COMPRESSION` | `false` | Disable gzip (use behind nginx) |
| `--allowed-rpcs` | `ALLOWED_RPCS` | (see below) | Comma-separated RPC whitelist |
| `--addr-index` | `ADDR_INDEX` | `false` | Enable the transparent address index + `/api/v2` |
| `--sapling-params-dir` | `SAPLING_PARAMS_DIR` | `$HOME/.pivx-params` | Directory with `sapling-{output,spend}.params` to serve |
| `--addr-index-path` | `ADDR_INDEX_PATH` | `addr_index.redb` | Address index database (mainnet) |
| `--testnet-addr-index-path` | `TESTNET_ADDR_INDEX_PATH` | `addr_index.testnet.redb` | Address index database (testnet) |

Default allowed RPCs: `getblockcount`, `getblockhash`, `getblock`, `getrawtransaction`, `sendrawtransaction`, `getmasternodecount`, `listmasternodes`, `getbudgetprojection`, `getbudgetinfo`, `getbudgetvotes`

## Persistence

The bridge writes two files in the working directory:

- **`shield.bin`** — Pre-encoded binary shield stream (append-only, survives restarts)
- **`shield_index.json`** — Block height to byte offset index (PivxNodeController `shield.json` compatible)

On startup, `shield.bin` is validated and truncated to the last complete block footer if a previous run crashed mid-write.

## Testing

```bash
cargo test    # 44 tests (includes real mainnet tx validation)
cargo clippy  # Zero warnings
```

## Migrating from PivxNodeController

1. Download the [latest release](https://github.com/PIVX-Labs/pivx-bridge/releases) or build from source
2. Copy your `.env` credentials (same format)
3. Copy `shield.bin` and `shield.json` from PivxNodeController (rename `shield.json` to `shield_index.json`)
4. Install `jq` on the server (`apt install jq`) for RPC proxy filter support
5. Point your reverse proxy at the bridge instead of the Node.js server
6. MPW connects unchanged — the binary protocol and API are identical

## License

MIT

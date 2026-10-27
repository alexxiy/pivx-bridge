<p align="center">
  <strong>PIVX Bridge</strong><br>
  <em>High-performance shield sync server for the PIVX network.</em><br>
  <em>Drop-in replacement for PivxNodeController, written in Rust.</em>
</p>

---

A shield sync bridge that connects to a PIVX full node, scans for Sapling shielded transactions, and serves compact shield data to light wallets over HTTP. Fully compatible with [MyPIVXWallet](https://github.com/PIVX-Labs/MyPIVXWallet) — zero client changes required. With the optional transparent address index it is also the only backend PIVXie needs.

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

- **Streamed from disk** — `getshielddata` streams the requested byte range of `shield.bin` in 1 MB chunks. Nothing is copied into the process per request, so memory stays flat however many wallets sync at once; the OS page cache keeps the hot part in RAM
- **No gzip on shield data** — the stream is random-looking (gzip saves under 2 %), so it goes out uncompressed with an exact `Content-Length`; JSON answers are still gzipped
- **Indexed offsets** — a small redb database maps each shield block to its offset in all three stream formats, so start offsets and lengths are O(log n) lookups
- **Parallel catch-up** — 4 RPC workers per index fetch blocks and read them, while one thread stores them in order and commits every 1000 blocks; a restart resumes where it stopped
- **Raw blocks** — the shield index reads blocks raw (`getblock` verbosity 0): a third of the bytes of their JSON, and about half the node's CPU. Each block's transactions are checked against its merkle root (a block that doesn't match is read as JSON instead). Only the last 1000 blocks are read as JSON, for the proxy's block cache
- **ZMQ + polling** — new blocks indexed instantly via ZMQ hashblock notifications, with a 10s polling safety net that catches anything ZMQ misses
- **Block hash LRU cache** — the last 1,000 height→hash mappings are cached in memory. `getblockhash` proxy calls serve from cache in <0.01ms instead of ~1ms RPC round-trips. On production traffic, ~50% of proxy calls are cache hits
- **Block cache** — `getblock` answers for recent blocks are kept as JSON bytes (1000 answers, 64 MB at most). MyPIVXWallet's filtered `getblock` and PIVXie's verbosity 1 are answered from them without jq
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

The bridge scans from Sapling activation (block 2,700,501) on first run, then indexes new blocks in real-time via ZMQ. It answers requests while it catches up, from the blocks indexed so far. It also starts while the node is still loading or not up yet (after a reboot, say): the indexers wait for the node and carry on when it answers.

### As a systemd service

[`contrib/pivx-bridge.service`](contrib/pivx-bridge.service) runs the bridge from `/opt/pivx-bridge` as its own `pivx-bridge` user, after `pivxd.service`, with systemd's sandboxing on. The install steps are at the top of the file:

```bash
sudo useradd --system --home-dir /opt/pivx-bridge --shell /usr/sbin/nologin pivx-bridge
sudo install -d -m 750 -o pivx-bridge -g pivx-bridge /opt/pivx-bridge
sudo install -m 755 target/release/pivx-bridge /opt/pivx-bridge/
sudo install -m 640 -g pivx-bridge .env.sample /opt/pivx-bridge/.env
sudo nano /opt/pivx-bridge/.env
sudo install -m 644 contrib/pivx-bridge.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now pivx-bridge
```

`/opt/pivx-bridge` holds the binary, `.env` and the data files (see [Persistence](#persistence)). Home directories are read-only to the service, so put the Sapling parameters somewhere the `pivx-bridge` user can read and set `SAPLING_PARAMS_DIR`. `/opt/sapling-params` (mode 755, files 644) works for the bridge and for nginx.

### Behind nginx

[`contrib/nginx-pivx-bridge.conf`](contrib/nginx-pivx-bridge.conf) puts HTTPS, HTTP/2 and gzip (brotli too, if your nginx has the module) in front of a bridge listening on localhost only (`LISTEN=127.0.0.1`, `NO_COMPRESSION=true`). It takes long transaction URLs, streams shield data straight through, keeps `/watch` long-polls open and sends the Sapling parameters from disk itself (from `/opt/sapling-params`). It keeps addresses and xpubs out of nginx's logs and client IPs away from the bridge. Each open wallet holds a `/watch` request and two nginx connections, so raise `worker_connections` in `nginx.conf` as the config's header says.

Exposed directly, the bridge closes connections that send no request within 30 s (idle kept-alive ones too), and requests whose body stalls for 30 s. Behind nginx the same 30 s applies to nginx's own connections, which nginx keeps idle for 60 s unless told otherwise. The sample config sets `keepalive_timeout 25s` in its `upstream` block for this; keep that line in your own config.

## PIVX Node Configuration

Add to `pivx.conf`:

```
server=1
rpcuser=rpc
rpcpassword=rpc
zmqpubhashblock=tcp://127.0.0.1:28332
# More RPC calls at once than pivxd's defaults (4 threads, a queue of 16):
# the bridge's indexers and the wallets' requests share them.
rpcthreads=8
rpcworkqueue=64
```

The bridge itself keeps to that: its indexers fetch blocks 4 at a time each, and client requests that call the node (proxy calls, broadcasts, transaction details) run at most `NODE_CALLS` (4) at once per network. Others wait up to 10 s, then get 503. `/getblockcount` asks the node at most once a second.

## API

All endpoints are served at both `/mainnet/...` and `/...` (without prefix).

### Shield Sync

| Route | Method | Description |
|-------|--------|-------------|
| `/mainnet/getshielddata?startBlock=N` | GET | Binary shield stream |
| `/mainnet/getshielddatalength?startBlock=N&endBlock=M` | GET | Byte count (for progress bars) |
| `/mainnet/getshieldblocks` | GET | JSON array of shield block heights |
| `/mainnet/sendrawtransaction` | POST | Broadcast raw transaction hex |
| `/mainnet/address_index` | GET | SQLite address index for MPW-Tauri (served when `address_index.sqlite` is in the working directory) |
| `/mainnet/sapling-output.params`, `/mainnet/sapling-spend.params` | GET | Sapling proving parameters for wallets that build shield transactions (served when found, see `SAPLING_PARAMS_DIR`) |

### RPC Proxy

| Route | Method | Description |
|-------|--------|-------------|
| `/mainnet/:method?params=a,b,c&filter=<jq>` | GET | Proxied RPC call with optional jq filtering |

The proxy validates methods against a configurable whitelist. Parameters are automatically type-coerced (numbers, booleans, strings); a JSON array (`params=["a,b",1]`) is passed as is. The `filter` parameter is evaluated in-process (jaq). By default only the filters MyPIVXWallet and PIVXie send are accepted (`JQ_FILTERS=known`): an arbitrary jq program can loop forever or build huge values from one request. `JQ_FILTERS=any` accepts every filter (for bridges only trusted clients use), `off` none.

### Transparent Address Index (opt-in, `ADDR_INDEX=true`)

Transparent history, balances and UTXOs for addresses and BIP44 account xpubs, so light wallets need no separate explorer. Answers follow Blockbook's format (the subset light wallets use; amounts are satoshi strings).

| Route | Method | Description |
|-------|--------|-------------|
| `/mainnet/status` | GET | Index status (`index.inSync`, `backend.chain`, `backend.blocks`, `bestBlockHash`) |
| `/mainnet/address/{address}` | GET | Address balance + history (`page`, `pageSize`, `from`, `to`, `details=basic\|txids\|txs`) |
| `/mainnet/xpub/{xpub}` | GET | BIP44 account xpub, gap-limit walk of chains 0/1 (`gap`, `tokens=nonzero\|used\|derived`, `details=…\|tokens\|tokenBalances`) |
| `/mainnet/utxo/{address\|xpub}` | GET | Unspent outputs incl. mempool (`confirmed=true` to exclude); coinbase/coinstake outputs are flagged |
| `/mainnet/tx/{txid}` | GET | Transaction with resolved input addresses/values, `hex`, fees, shield value balance |
| `/mainnet/block-index/{height}` | GET | Block hash at height |
| `/mainnet/sendtx` | POST / GET `/sendtx/{hex}` | Broadcast |
| `/mainnet/watch` | POST | Long-poll for changes (see below) |

Every address the node decodes is indexed — P2PKH, P2SH, P2PK, exchange (`EXM…`) and both the staker and owner of cold-stake (P2CS) outputs. Unconfirmed transactions are tracked from the node's mempool. Reorgs are rolled back exactly (block hashes and undo data for the last 1000 blocks are kept). Transaction details for a history page are fetched from the node in JSON-RPC batches.

`/watch` lets wallets react within ~2 s instead of polling. POST a JSON body `{"height", "hash"?, "mempoolSeq"?, "addresses": [...], "timeout"?}`; the bridge answers as soon as a block other than `height`/`hash` is indexed or a mempool tx touching one of `addresses` arrives after `mempoolSeq`, otherwise after `timeout` seconds (default 25, max 120). The answer is `{height, hash, mempoolSeq, newBlock, txids, reset, changed}`; send its `height`, `hash` and `mempoolSeq` with the next call. `reset: true` means the bridge does not know the client's `mempoolSeq` (it restarted, or the client fell more than 10 000 mempool arrivals behind) and the client should do a full refresh. Omit `mempoolSeq` on the first call.

The index lives in its own `addr_index.redb` (redb, pure Rust), is built by its own thread and never touches the shield stream. The first run indexes the whole chain from genesis; progress is visible at `/status`. The node needs `txindex=1` (PIVX's default) for transaction details.

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
  main.rs         Startup, ZMQ listener threads, routes, HTTP server with timeouts
  config.rs       CLI args + .env configuration
  rpc.rs          JSON-RPC 1.0 client (auth, connection pooling, batches, 30 s timeout)
  scanner.rs      Block scanner + PIVX v3 Sapling tx parser (validated against PIVX Core)
  stream.rs       Binary stream encoder + compact conversion (PivxCompat / Compact / CompactPlus)
  shield_store.rs shield.bin + redb index (offsets, cursor, recent hashes), crash-safe commits
  shield_sync.rs  Shield indexer thread: parallel catch-up, exact reorg rollback
  fetch.rs        Block fetch workers for both indexers' catch-up
  api.rs          Shield endpoints, streamed from disk + block hash LRU cache
  proxy.rs        RPC proxy with jq filtering (jaq) + response timing
  addr_index/   Transparent address index (opt-in)
    store.rs    redb tables: outputs, per-address history/UTXOs/stats, undo
    mod.rs      Indexer thread: parallel catch-up, reorg rollback, mempool
    xpub.rs     BIP32 public derivation + P2PKH encoding for xpub queries
    api.rs      /status, /address, /xpub, /utxo, /tx, /sendtx, /watch
```

## Configuration

All options support both CLI flags and environment variables:

| Flag | Env | Default | Description |
|------|-----|---------|-------------|
| `--rpc-url` | `RPC_URL` | `http://127.0.0.1:51473` | PIVX node RPC endpoint |
| `--rpc-user` | `RPC_USER` | `rpc` | RPC username |
| `--rpc-pass` | `RPC_PASS` | `rpc` | RPC password |
| `--zmq-url` | `ZMQ_URL` | `tcp://127.0.0.1:28332` | ZMQ hashblock endpoint |
| `--testnet-rpc-url` | `TESTNET_RPC_URL` | — | Testnet node RPC (enables `/testnet/`); `TESTNET_RPC_USER` / `TESTNET_RPC_PASS` default to the mainnet ones |
| `--testnet-zmq-url` | `TESTNET_ZMQ_URL` | — | Testnet ZMQ endpoint (without it testnet checks for blocks every 10 s) |
| `--port` | `PORT` | `3000` | HTTP server port |
| `--listen` | `LISTEN` | `0.0.0.0` | Comma-separated IP addresses to listen on, IPv4 and/or IPv6 (`127.0.0.1` behind nginx, `0.0.0.0,::` for all) |
| `--sapling-height` | `SAPLING_HEIGHT` | `2700501` | Sapling activation block (regtest: 301) |
| `--testnet-sapling-height` | `TESTNET_SAPLING_HEIGHT` | `501` | Sapling activation block on testnet |
| `--jq-filters` | `JQ_FILTERS` | `known` | Which proxy `filter`s run: `known`, `any` or `off` |
| `--no-compression` | `NO_COMPRESSION` | `false` | Disable gzip of JSON answers (use behind nginx) |
| `--log-file` | `LOG_FILE` | `pivx-bridge.log` | Log file, `-` for stderr |
| `--log-level` | `LOG_LEVEL` | `info` | `error`, `warn`, `info`, or `debug` (adds every RPC proxy call and broadcast txid) |
| `--log-max-mb` | `LOG_MAX_MB` | `50` | Size at which the log is rotated (`0`: never) |
| `--log-keep` | `LOG_KEEP` | `5` | Rotated logs kept (`pivx-bridge.log.1` is the newest) |
| `--node-calls` | `NODE_CALLS` | `4` | Client requests calling the node at once, per network; more wait up to 10 s, then get 503 |
| `--allowed-rpcs` | `ALLOWED_RPCS` | (see below) | Comma-separated RPC whitelist |
| `--addr-index` | `ADDR_INDEX` | `false` | Enable the transparent address index |
| `--sapling-params-dir` | `SAPLING_PARAMS_DIR` | `$HOME/.pivx-params` | Directory with `sapling-{output,spend}.params` to serve |
| `--addr-index-path` | `ADDR_INDEX_PATH` | `addr_index.redb` | Address index database (mainnet) |
| `--addr-index-prune` | `ADDR_INDEX_PRUNE` | `false` | Drop spent outputs once 1,000 blocks deep: a smaller index, but transaction details then ask the node for the transactions those inputs spent |
| `--testnet-addr-index-path` | `TESTNET_ADDR_INDEX_PATH` | `addr_index.testnet.redb` | Address index database (testnet) |

Default allowed RPCs: `getblockcount`, `getblockhash`, `getblock`, `getrawtransaction`, `sendrawtransaction`, `getmasternodecount`, `listmasternodes`, `relaymasternodebroadcast`, `getnetworkinfo`, `getbudgetprojection`, `getbudgetinfo`, `getbudgetvotes`, `mnbudgetrawvote`, `submitbudget`

## Logging

The bridge logs to `pivx-bridge.log` in the working directory, nothing to stdout or stderr (`LOG_FILE=-` logs to stderr instead). Each line has a UTC timestamp and a level:

```
2026-10-16 14:06:39.709Z INFO  Listening on http://127.0.0.1:3000
2026-10-16 14:06:45.735Z DEBUG [proxy 0.48ms] getblockhash
```

`info` logs startup, indexing progress, new shield blocks, reorgs and node problems; `debug` adds a line per RPC proxy call and the txid of each broadcast. Client IPs and the addresses, xpubs and transactions wallets look up are never logged. A panic is logged too, and also goes to stderr so the service manager shows why the bridge stopped. If the log file can't be opened, the bridge says so on stderr and exits.

## Stopping and restarting

On SIGTERM (`systemctl stop`) or Ctrl-C the indexers finish the commit they're in and the bridge exits, within 20 s. Every database commit also saves redb's allocator state (quick-repair), so even after a kill or a crash the databases open at once instead of being checked in full. The server starts answering before the address index has opened; until then the index's routes answer 503.

If an indexer thread panics, the bridge logs it and exits with status 1 rather than go on serving data that no longer follows the chain; the systemd unit in `contrib/` restarts it (`Restart=on-failure`). A panic while answering a request only fails that request.

## Persistence

The bridge writes these files in the working directory (testnet: `shield.testnet.*`, `addr_index.testnet.redb`):

- **`shield.bin`** — the PIVX-compat shield stream (append-only), served by byte range
- **`shield.redb`** — per shield block, its offset in each stream format; the scan cursor; hashes of the last 1000 scanned blocks (exact reorg detection, also across restarts)
- **`addr_index.redb`** — the transparent address index (only with `ADDR_INDEX=true`). It records which chain it indexes, so it opens without the node; if the node turns out to be on another chain (RPC pointed at the wrong network), the bridge exits instead of indexing it. With `ADDR_INDEX_PRUNE=true`, outputs spent more than 1,000 blocks ago are dropped as the index grows (on regtest that left a third of them); turning it on doesn't shrink an existing index, a rebuild does

New blocks are appended to `shield.bin` and fsynced before one database transaction records them, so on startup `shield.bin` is simply cut back to the recorded length. Deleting `shield.redb` (or a database from an incompatible version) makes the bridge rebuild the shield data from scratch.

## Testing

```bash
cargo test                                  # includes real mainnet tx validation
cargo clippy --all-targets -- -D warnings   # zero warnings
```

## Migrating from PivxNodeController

1. Download the [latest release](https://github.com/PIVX-Labs/pivx-bridge/releases) or build from source
2. Copy your `.env` credentials (same format)
3. Point your reverse proxy at the bridge instead of the Node.js server
4. MPW connects unchanged — the binary protocol and API are identical

The bridge builds its own shield data on first start (it does not reuse PivxNodeController's `shield.bin`); until it has caught up, wallets get the blocks indexed so far.

## License

MIT, see [LICENSE](LICENSE).

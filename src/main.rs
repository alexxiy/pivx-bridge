/// PIVX Bridge — drop-in replacement for PivxNodeController.
///
/// Connects to a PIVX full node, scans for Sapling transactions, and serves
/// shield data to light wallets (MyPIVXWallet, PIVXie) over HTTP.
mod addr_index;
mod api;
mod block_cache;
mod config;
mod db;
mod fetch;
mod hex;
mod logging;
mod proxy;
mod rpc;
mod scanner;
mod shield_store;
mod shield_sync;
mod shutdown;
mod stream;

use std::sync::atomic::{AtomicBool, AtomicU32};
use std::sync::{mpsc, Arc, Mutex, RwLock};
use std::time::Duration;

use axum::routing::{get, post};
use axum::Router;
use clap::Parser;
use tower_http::compression::predicate::{NotForContentType, Predicate};
use tower_http::compression::{predicate::DefaultPredicate, CompressionLayer};
use tower_http::cors::CorsLayer;
use tower_http::services::ServeFile;

use addr_index::api::AddrSlot;
use shield_sync::RpcConfig;

/// Per-network settings.
struct NetworkConfig {
    label: &'static str,
    rpc: RpcConfig,
    zmq_url: Option<String>,
    /// File name prefix: `shield` or `shield.testnet`.
    files: &'static str,
    sapling_height: u32,
    addr_index_path: Option<String>,
}

/// Open the shield store, start its indexer (catch-up runs in the
/// background, the server answers from what is indexed so far) and build
/// the network's routes.
fn start_network(cfg: NetworkConfig, config: &config::Config) -> Router {
    let label = cfg.label;
    let store = shield_store::ShieldStore::open(
        label,
        &format!("{}.redb", cfg.files),
        &format!("{}.bin", cfg.files),
        cfg.sapling_height,
    )
    .unwrap_or_else(|e| panic!("[{label}] shield store: {e}"));
    let cursor = store.cursor();
    log::info!(
        "[{label}] Shield store: {} shield blocks, scanned to {}",
        store.block_count().unwrap_or(0),
        cursor.height
    );

    let node_calls = Arc::new(tokio::sync::Semaphore::new(config.node_calls as usize));
    let state = Arc::new(api::AppState {
        label,
        rpc: cfg.rpc.client(),
        store,
        allowed_rpcs: config.allowed_rpc_set(),
        hash_cache: RwLock::new(api::HashCache::new(1000)),
        block_cache: RwLock::new(block_cache::BlockCache::new(1000, 64 << 20)),
        chain_height: AtomicU32::new(0),
        node_behind: AtomicBool::new(false),
        jq: proxy::JqPolicy::new(config.jq_filters),
        node_calls: node_calls.clone(),
        block_count: Mutex::new(None),
    });
    let trigger = shield_sync::spawn(state.clone(), cfg.rpc.clone());
    match cfg.zmq_url {
        Some(url) => spawn_zmq_listener(label, url, trigger),
        None => log::info!("[{label}] No ZMQ endpoint: checking for blocks every 10 s"),
    }

    let mut routes = Router::new()
        .route("/getshielddata", get(api::get_shield_data))
        .route("/getshielddatalength", get(api::get_shield_data_length))
        .route("/getblockcount", get(api::get_block_count))
        .route("/getshieldblocks", get(api::get_shield_blocks))
        .route("/sendrawtransaction", post(api::send_raw_transaction))
        // SQLite address index for MPW-Tauri, when the operator provides one.
        .route_service("/address_index", ServeFile::new("address_index.sqlite"))
        .route("/{method}", get(proxy::rpc_proxy))
        .with_state(state);
    if let Some(dir) = sapling_params_dir(config) {
        routes = routes
            .route_service("/sapling-output.params", ServeFile::new(dir.join("sapling-output.params")))
            .route_service("/sapling-spend.params", ServeFile::new(dir.join("sapling-spend.params")));
    }
    if let Some(path) = cfg.addr_index_path {
        let slot = Arc::new(AddrSlot::new());
        routes = routes.merge(addr_index::api::routes(slot.clone()));
        start_addr_index(label, path, cfg.rpc, config.addr_index_prune, node_calls, slot);
    }
    routes
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

/// Wake the shield indexer on every ZMQ hashblock notification.
fn spawn_zmq_listener(label: &'static str, zmq_url: String, trigger: mpsc::Sender<()>) {
    tokio::spawn(async move {
        use futures::StreamExt;

        loop {
            log::info!("[{label}] ZMQ subscribing to {zmq_url}...");
            let mut subscriber = match bitcoincore_zmq::subscribe_async(&[&zmq_url]) {
                Ok(s) => s,
                Err(e) => {
                    log::warn!("[{label}] ZMQ failed: {e} — checking every 10 s, retrying in 30 s");
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    continue;
                }
            };
            while let Some(msg) = subscriber.next().await {
                match msg {
                    Ok(bitcoincore_zmq::Message::HashBlock(_, _)) => {
                        let _ = trigger.send(());
                    }
                    Ok(_) => {}
                    Err(e) => {
                        log::warn!("[{label}] ZMQ error: {e} — reconnecting");
                        break;
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });
}

/// Open the address index in the background, then start its indexer and
/// put it in `slot` for its routes. A large index may take a while to
/// open; meanwhile the rest of the bridge answers, and the index's routes
/// say 503. Exits the process if the index can't be opened (an operator
/// who asked for it should notice). A node that is still starting isn't a
/// reason: the index waits for it.
fn start_addr_index(
    label: &'static str,
    path: String,
    rpc: RpcConfig,
    prune: bool,
    node_calls: Arc<tokio::sync::Semaphore>,
    slot: Arc<AddrSlot>,
) {
    std::thread::Builder::new()
        .name(format!("addr-open-{label}"))
        .spawn(move || {
            let idx = match addr_index::AddrIndex::open(label, &path, &rpc, prune, node_calls) {
                Ok(idx) => idx,
                Err(_) if shutdown::stopping() => return,
                Err(e) => {
                    log::error!("[{label}] The address index failed to open: {e}");
                    std::process::exit(1);
                }
            };
            idx.spawn(rpc);
            let _ = slot.set(idx);
            log::info!("[{label}] Address index: enabled");
        })
        .expect("spawn address index opener");
}

#[tokio::main]
async fn main() {
    let _ = dotenvy::dotenv();
    let config = config::Config::parse();
    if let Err(e) = logging::init(&config) {
        eprintln!("pivx-bridge: {e}");
        std::process::exit(1);
    }

    log::info!("PIVX Bridge v{} starting", env!("CARGO_PKG_VERSION"));
    log::info!("RPC: {}", config.rpc_url);
    log::info!("ZMQ: {}", config.zmq_url);
    match sapling_params_dir(&config) {
        Some(d) => log::info!("Sapling params: serving from {}", d.display()),
        None => log::info!("Sapling params: not found (set SAPLING_PARAMS_DIR to serve them)"),
    }

    // -- Mainnet --
    let mainnet_routes = start_network(
        NetworkConfig {
            label: "mainnet",
            rpc: RpcConfig {
                url: config.rpc_url.clone(),
                user: config.rpc_user.clone(),
                pass: config.rpc_pass.clone(),
            },
            zmq_url: Some(config.zmq_url.clone()),
            files: "shield",
            sapling_height: config.sapling_height,
            addr_index_path: config.addr_index.then(|| config.addr_index_path.clone()),
        },
        &config,
    );
    let mut app = Router::new().nest("/mainnet", mainnet_routes.clone()).merge(mainnet_routes);

    // -- Testnet (optional) --
    if let Some(testnet_url) = &config.testnet_rpc_url {
        let testnet_routes = start_network(
            NetworkConfig {
                label: "testnet",
                rpc: RpcConfig {
                    url: testnet_url.clone(),
                    user: config.testnet_rpc_user.clone().unwrap_or_else(|| config.rpc_user.clone()),
                    pass: config.testnet_rpc_pass.clone().unwrap_or_else(|| config.rpc_pass.clone()),
                },
                zmq_url: config.testnet_zmq_url.clone(),
                files: "shield.testnet",
                sapling_height: config.testnet_sapling_height,
                addr_index_path: config.addr_index.then(|| config.testnet_addr_index_path.clone()),
            },
            &config,
        );
        app = app.nest("/testnet", testnet_routes);
        log::info!("Testnet: enabled at /testnet/");
    }

    // -- Layers --
    let app = app.layer(CorsLayer::permissive());

    let app = if config.no_compression {
        log::info!("Compression: off");
        app
    } else {
        // Shield data and Sapling params are random-looking (gzip saves
        // under 2 %) and large: compressing them only costs CPU and delays
        // the first byte. JSON answers are compressed.
        log::info!("Compression: gzip for JSON (NO_COMPRESSION=true turns it off)");
        let predicate = DefaultPredicate::new().and(NotForContentType::const_new("application/octet-stream"));
        app.layer(CompressionLayer::new().compress_when(predicate))
    };

    let mut servers = Vec::new();
    for ip in &config.listen {
        let addr = std::net::SocketAddr::new(*ip, config.port);
        let listener = bind(addr).unwrap_or_else(|e| panic!("failed to listen on {addr}: {e}"));
        log::info!("Listening on http://{addr}");
        servers.push(tokio::spawn(serve(listener, app.clone())));
    }
    tokio::select! {
        results = futures::future::join_all(servers) => {
            for result in results {
                result.expect("server task failed");
            }
        }
        () = shutdown::signal() => {}
    }

    // The indexers finish the commit they're in (systemd waits 30 s).
    log::info!("Stopping");
    let all = tokio::task::spawn_blocking(|| shutdown::stop(Duration::from_secs(20))).await.unwrap_or(false);
    if all {
        log::info!("Stopped");
    } else {
        log::warn!("Stopped while an indexer was still waiting on the node (what it stored is saved)");
    }
    std::process::exit(0);
}

/// How long a client may take to send a request's headers, and how long
/// an idle kept-alive connection stays open.
const HEADER_TIMEOUT: Duration = Duration::from_secs(30);
/// How long a request body may stall between two pieces.
const BODY_TIMEOUT: Duration = Duration::from_secs(30);

/// Serves `app` on `listener`. Unlike `axum::serve`, with timeouts: a
/// connection that doesn't send its request (slowly or not at all) is
/// closed, so clients can't hold connections open forever when the
/// bridge isn't behind nginx.
async fn serve(listener: tokio::net::TcpListener, app: Router) {
    use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
    use hyper_util::server::conn::auto::Builder;
    use hyper_util::service::TowerToHyperService;
    use std::io::ErrorKind;
    use tower_http::timeout::RequestBodyTimeout;

    let mut builder = Builder::new(TokioExecutor::new());
    builder.http1().timer(TokioTimer::new()).header_read_timeout(HEADER_TIMEOUT);
    builder.http2().timer(TokioTimer::new()).keep_alive_interval(HEADER_TIMEOUT);
    let builder = Arc::new(builder);
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e) if matches!(e.kind(), ErrorKind::ConnectionAborted | ErrorKind::ConnectionReset) => continue,
            Err(e) => {
                // Out of file descriptors and the like: wait, don't spin.
                log::warn!("Accepting a connection failed: {e}");
                tokio::time::sleep(Duration::from_secs(1)).await;
                continue;
            }
        };
        let _ = stream.set_nodelay(true);
        let service = TowerToHyperService::new(RequestBodyTimeout::new(app.clone(), BODY_TIMEOUT));
        let builder = builder.clone();
        tokio::spawn(async move {
            // hyper's timeout runs once a request starts; telling HTTP/1
            // from HTTP/2 waits for the first byte without one.
            let mut first = [0u8; 1];
            if !matches!(tokio::time::timeout(HEADER_TIMEOUT, stream.peek(&mut first)).await, Ok(Ok(1))) {
                return;
            }
            let _ = builder.serve_connection_with_upgrades(TokioIo::new(stream), service).await;
        });
    }
}

/// A listening socket on [addr]. IPv6 ones take IPv6 only, so `0.0.0.0`
/// and `::` can both be listened on.
fn bind(addr: std::net::SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    use socket2::{Domain, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
    if addr.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    tokio::net::TcpListener::from_std(socket.into())
}

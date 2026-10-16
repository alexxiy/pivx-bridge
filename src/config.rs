/// CLI configuration — command-line args with env var fallbacks.
use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[command(name = "pivx-bridge", about = "PIVX shield sync bridge")]
pub struct Config {
    /// PIVX node RPC URL
    #[arg(long, env = "RPC_URL", default_value = "http://127.0.0.1:51473")]
    pub rpc_url: String,

    /// RPC username
    #[arg(long, env = "RPC_USER", default_value = "rpc")]
    pub rpc_user: String,

    /// RPC password
    #[arg(long, env = "RPC_PASS", default_value = "rpc")]
    pub rpc_pass: String,

    /// Testnet RPC URL (enables /testnet/ routes)
    #[arg(long, env = "TESTNET_RPC_URL")]
    pub testnet_rpc_url: Option<String>,

    /// Testnet RPC username
    #[arg(long, env = "TESTNET_RPC_USER")]
    pub testnet_rpc_user: Option<String>,

    /// Testnet RPC password
    #[arg(long, env = "TESTNET_RPC_PASS")]
    pub testnet_rpc_pass: Option<String>,

    /// ZMQ endpoint for hashblock notifications
    #[arg(long, env = "ZMQ_URL", default_value = "tcp://127.0.0.1:28332")]
    pub zmq_url: String,

    /// ZMQ endpoint of the testnet node (without it testnet polls every 10 s)
    #[arg(long, env = "TESTNET_ZMQ_URL")]
    pub testnet_zmq_url: Option<String>,

    /// HTTP server port
    #[arg(long, env = "PORT", default_value_t = 3000)]
    pub port: u16,

    /// Comma-separated IP addresses to listen on, IPv4 and/or IPv6 (e.g.
    /// `127.0.0.1` behind nginx, or `0.0.0.0,::` for every address)
    #[arg(long, env = "LISTEN", value_delimiter = ',', value_parser = parse_ip, default_value = "0.0.0.0")]
    pub listen: Vec<std::net::IpAddr>,

    /// Comma-separated list of allowed RPC methods for the proxy
    #[arg(long, env = "ALLOWED_RPCS", default_value = "getblockcount,getblockhash,getblock,getrawtransaction,sendrawtransaction,getmasternodecount,listmasternodes,relaymasternodebroadcast,getnetworkinfo,getbudgetprojection,getbudgetinfo,getbudgetvotes,mnbudgetrawvote,submitbudget")]
    pub allowed_rpcs: String,

    /// Sapling activation height (mainnet)
    #[arg(long, env = "SAPLING_HEIGHT", default_value_t = 2_700_501)]
    pub sapling_height: u32,

    /// Sapling activation height (testnet)
    #[arg(long, env = "TESTNET_SAPLING_HEIGHT", default_value_t = 501)]
    pub testnet_sapling_height: u32,

    /// Which jq filters the RPC proxy runs: known (the ones MyPIVXWallet
    /// and PIVXie send), any, or off
    #[arg(long, env = "JQ_FILTERS", value_enum, default_value = "known")]
    pub jq_filters: crate::proxy::JqMode,

    /// Enable the transparent address index (`/address`, `/xpub`, `/utxo`,
    /// `/tx`, ...). The first run indexes the whole chain.
    #[arg(long, env = "ADDR_INDEX")]
    pub addr_index: bool,

    /// Address index database path (mainnet)
    #[arg(long, env = "ADDR_INDEX_PATH", default_value = "addr_index.redb")]
    pub addr_index_path: String,

    /// Address index database path (testnet)
    #[arg(long, env = "TESTNET_ADDR_INDEX_PATH", default_value = "addr_index.testnet.redb")]
    pub testnet_addr_index_path: String,

    /// Directory holding sapling-output.params / sapling-spend.params to
    /// serve to wallets (defaults to $HOME/.pivx-params when present)
    #[arg(long, env = "SAPLING_PARAMS_DIR")]
    pub sapling_params_dir: Option<String>,

    /// Disable gzip compression of JSON answers (use when behind nginx or
    /// another compressing proxy). Shield data is never compressed.
    #[arg(long, env = "NO_COMPRESSION")]
    pub no_compression: bool,
}

/// An IP address, IPv6 with or without brackets (`::1`, `[::1]`).
fn parse_ip(s: &str) -> Result<std::net::IpAddr, String> {
    let s = s.trim();
    let bare = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')).unwrap_or(s);
    bare.parse().map_err(|_| format!("not an IP address: {s}"))
}

impl Config {
    pub fn allowed_rpc_set(&self) -> Vec<String> {
        self.allowed_rpcs.split(',').map(|s| s.trim().to_string()).collect()
    }
}

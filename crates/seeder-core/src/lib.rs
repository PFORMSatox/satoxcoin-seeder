pub mod config;
pub mod db;
pub mod explorer;
pub mod net;
pub mod p2p;
pub mod serialize;

use std::sync::OnceLock;


pub const NODE_NETWORK: u64 = 1 << 0;
pub const NODE_BLOOM: u64 = 1 << 2;
pub const NODE_WITNESS: u64 = 1 << 3;
pub const NODE_COMPACT_FILTERS: u64 = 1 << 6;
pub const NODE_NETWORK_LIMITED: u64 = 1 << 10;
pub const INIT_PROTO_VERSION: u32 = 209;

pub const DEFAULT_FILTERS: [u64; 9] = [
    NODE_NETWORK,
    NODE_NETWORK | NODE_BLOOM,
    NODE_NETWORK | NODE_WITNESS,
    NODE_NETWORK | NODE_WITNESS | NODE_COMPACT_FILTERS,
    NODE_NETWORK | NODE_WITNESS | NODE_BLOOM,
    NODE_NETWORK_LIMITED,
    NODE_NETWORK_LIMITED | NODE_BLOOM,
    NODE_NETWORK_LIMITED | NODE_WITNESS,
    NODE_NETWORK_LIMITED | NODE_WITNESS | NODE_COMPACT_FILTERS,
];

static APP_STATE: OnceLock<AppState> = OnceLock::new();

#[derive(Debug, Clone)]
pub struct AppState {
    pub protocol_version: u32,
    pub init_proto_version: u32,
    pub min_peer_proto_version: i32,
    pub caddr_time_version: u32,
    pub message_start: [u8; 4],
    pub wallet_port: u16,
    pub app_name: String,
    pub current_block: i32,
    pub block_from_explorer: bool,
}

impl AppState {
    pub fn new(cfg: &config::Config) -> Self {
        AppState {
            protocol_version: cfg.protocol_version,
            init_proto_version: cfg.init_proto_version,
            min_peer_proto_version: cfg.min_peer_proto_version as i32,
            caddr_time_version: cfg.caddr_time_version,
            message_start: cfg.pch_message_start,
            wallet_port: cfg.wallet_port,
            app_name: String::from("satoxcoin-seeder"),
            current_block: cfg.block_count,
            block_from_explorer: false,
        }
    }
}

pub fn init_app_state(cfg: &config::Config) {
    let _ = APP_STATE.set(AppState::new(cfg));
}

pub fn app_state() -> &'static AppState {
    APP_STATE.get().expect("AppState not initialized")
}

pub fn cfg_message_start() -> [u8; 4] {
    app_state().message_start
}

pub fn init_proto_version() -> u32 {
    app_state().init_proto_version
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn test_app_state_init() {
        let cfg = Config {
            protocol_version: 70028,
            init_proto_version: 209,
            min_peer_proto_version: 70025,
            caddr_time_version: 0,
            pch_message_start: [0x63, 0x56, 0x65, 0x65],
            wallet_port: 60777,
            explorer_url: None,
            second_explorer_url: None,
            explorer_requery_seconds: 600,
            block_count: 1000000,
            seeds: vec![],
            cf_domain: None,
            cf_domain_prefix: None,
            cf_api_token: None,
            cf_seed_dump: None,
            cf_max_seeds: None,
        };
        let state = AppState::new(&cfg);
        assert_eq!(state.protocol_version, 70028);
        assert_eq!(state.init_proto_version, 209);
        assert_eq!(state.min_peer_proto_version, 70025);
        assert_eq!(state.message_start, [0x63, 0x56, 0x65, 0x65]);
        assert_eq!(state.wallet_port, 60777);
        assert_eq!(state.current_block, 1000000);
        assert_eq!(state.app_name, "satoxcoin-seeder");
        assert!(!state.block_from_explorer);
    }

    #[test]
    fn test_node_constants() {
        assert_eq!(NODE_NETWORK, 1 << 0);
        assert_eq!(NODE_BLOOM, 1 << 2);
        assert_eq!(NODE_WITNESS, 1 << 3);
        assert_eq!(INIT_PROTO_VERSION, 209);
    }

    #[test]
    fn test_default_filters() {
        assert_eq!(DEFAULT_FILTERS.len(), 9);
        assert_eq!(DEFAULT_FILTERS[0], NODE_NETWORK);
    }


}

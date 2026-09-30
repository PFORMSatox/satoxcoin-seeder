//! Live P2P handshake test against a real Satoxcoin node.
//!
//! Requires network access to the seed network. Ignored by default:
//!   cargo test -p seeder --test live_handshake -- --ignored
use std::str::FromStr;

use seeder_core::config::Config;
use seeder_core::net::{NetAddr, Service};
use seeder_core::p2p::handshake::test_node;
use seeder_core::{init_app_state, NODE_NETWORK};

fn test_config() -> Config {
    Config::parse(
        r#"
protocol_version = "70028"
init_proto_version = "209"
min_peer_proto_version = "70025"
pchMessageStart_0 = "0x63"
pchMessageStart_1 = "0x56"
pchMessageStart_2 = "0x65"
pchMessageStart_3 = "0x65"
wallet_port = "60777"
block_count = "0"
"#,
    )
    .expect("test config parses")
}

#[tokio::test]
#[ignore]
async fn live_handshake_with_mainnet_seed_node() {
    init_app_state(&test_config());
    let svc = Service::new(NetAddr::from_str("65.108.219.177").unwrap(), 60777);
    let res = test_node(&svc, 0, false).await;
    assert_eq!(res.ban, 0, "node banned us");
    assert_eq!(res.client_version, 70028);
    assert!(
        res.services & NODE_NETWORK != 0,
        "NODE_NETWORK bit missing: {:08x}",
        res.services
    );
    assert!(
        res.client_sub_version.contains("Satoxcoin"),
        "unexpected subver: {}",
        res.client_sub_version
    );
}

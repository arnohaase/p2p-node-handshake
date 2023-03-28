use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use log::{info, LevelFilter};
use simple_logger::SimpleLogger;
use tokio::time::sleep;

use p2p_node_handshake::bitcoin::config::BitcoinConfig;
use p2p_node_handshake::bitcoin::error::BitcoinResult;
use p2p_node_handshake::bitcoin::protocol::BitcoinProtocol;
use p2p_node_handshake::bitcoin::types::{BitcoinNetworkId, BitcoinVersion, Services};
use p2p_node_handshake::generic::connection::Connection;
use p2p_node_handshake::generic::four_way_handshake::four_way_handshake;
use p2p_node_handshake::generic::protocol::GenericP2PConfig;

#[ignore = "requires a running bitcoind - run manually. See README.md for details"]
#[tokio::test]
async fn test_with_bitcoind() -> BitcoinResult<()> {
    SimpleLogger::new()
        .with_level(LevelFilter::Trace)
        .with_colors(true)
        .init()
        .unwrap();

    let client_config = Arc::new(BitcoinConfig {
        generic_config: GenericP2PConfig::new(SocketAddr::from_str("127.0.0.1:18002").unwrap()),
        my_version: BitcoinVersion(60002),
        my_bitcoin_network: BitcoinNetworkId::TestNetRegTest,
        my_services: Services::empty(),
        payload_size_limit: BitcoinConfig::DEFAULT_PAYLOAD_SIZE_LIMIT,
    });
    let mut client = Connection::<BitcoinProtocol>::connect(
        SocketAddr::from_str("127.0.0.1:18445").unwrap(),
        client_config,
    )
    .await?;
    let _negotiated = four_way_handshake(&mut client).await?;
    info!("handshake with bitcoind successful");

    // This is to give bitcoind time to receive our verack message, showing in its log that the
    //  handshake completed on its side as well
    sleep(Duration::from_secs(1)).await;

    Ok(())
}

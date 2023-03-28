use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use log::{info, LevelFilter};
use simple_logger::SimpleLogger;
use tokio::time::sleep;

use p2p_node_handshake::config::Config;
use p2p_node_handshake::connection::Connection;
use p2p_node_handshake::error::P2PResult;
use p2p_node_handshake::handshake::handshake;
use p2p_node_handshake::message::{BitcoinNetworkId, BitcoinVersion, Services};

#[ignore = "requires a running bitcoind - run manually. See README.md for details"]
#[tokio::test]
async fn test_with_bitcoind() -> P2PResult<()> {
    SimpleLogger::new()
        .with_level(LevelFilter::Trace)
        .with_colors(true)
        .init()
        .unwrap();

    let client_config = Arc::new(Config {
        my_address: SocketAddr::from_str("127.0.0.1:18002").unwrap(),
        my_version: BitcoinVersion(60002),
        my_bitcoin_network: BitcoinNetworkId::TestNetRegTest,
        my_services: Services::empty(),
        payload_size_limit: Config::DEFAULT_PAYLOAD_SIZE_LIMIT,
        read_buffer_capacity: Config::DEFAULT_BUFFER_CAPACITY,
        write_buffer_capacity: Config::DEFAULT_BUFFER_CAPACITY,
    });
    let mut client = Connection::connect(
        SocketAddr::from_str("127.0.0.1:18445").unwrap(),
        client_config,
    )
    .await?;
    let _negotiated = handshake(&mut client).await?;
    info!("handshake with bitcoind successful");

    // This is to give bitcoind time to receive our verack message, showing in its log that the
    //  handshake completed on its side as well
    sleep(Duration::from_secs(1)).await;

    Ok(())
}

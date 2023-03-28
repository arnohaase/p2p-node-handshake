use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use lazy_static::lazy_static;
use log::{info, LevelFilter};
use simple_logger::SimpleLogger;
use tokio::sync::oneshot;
use tokio::sync::Notify;

use p2p_node_handshake::bitcoin::config::BitcoinConfig;
use p2p_node_handshake::bitcoin::error::BitcoinResult;
use p2p_node_handshake::bitcoin::protocol::BitcoinProtocol;
use p2p_node_handshake::bitcoin::types::{BitcoinNetworkId, BitcoinVersion, Services};
use p2p_node_handshake::generic::connection::Connection;
use p2p_node_handshake::generic::four_way_handshake::*;
use p2p_node_handshake::generic::protocol::GenericP2PConfig;
use p2p_node_handshake::generic::server;

lazy_static! {
    static ref SERVER_HANDSHAKE_COMPLETE: Arc<Notify> = Arc::new(Notify::new());
}

#[tokio::test]
async fn test_client_server() -> BitcoinResult<()> {
    SimpleLogger::new()
        .with_level(LevelFilter::Trace)
        .with_colors(true)
        .init()
        .unwrap();

    let server_config = Arc::new(BitcoinConfig {
        generic_config: GenericP2PConfig::new(SocketAddr::from_str("127.0.0.1:18001").unwrap()),
        my_version: BitcoinVersion(60000),
        my_bitcoin_network: BitcoinNetworkId::TestNetRegTest,
        my_services: Services::NODE_XTHIN,
        payload_size_limit: BitcoinConfig::DEFAULT_PAYLOAD_SIZE_LIMIT,
    });

    let (server_running_sender, server_running_receiver) = oneshot::channel();

    tokio::spawn(server::listen(
        on_server_connection,
        server_running_sender,
        Arc::clone(&server_config),
    ));

    let client_config = Arc::new(BitcoinConfig {
        generic_config: GenericP2PConfig::new(SocketAddr::from_str("127.0.0.1:18002").unwrap()),
        my_version: BitcoinVersion(60001),
        my_bitcoin_network: BitcoinNetworkId::TestNetRegTest,
        my_services: Services::NODE_NETWORK,
        payload_size_limit: BitcoinConfig::DEFAULT_PAYLOAD_SIZE_LIMIT,
    });
    server_running_receiver.await.unwrap();
    let mut client = Connection::<BitcoinProtocol>::connect(
        server_config.generic_config.my_address.clone(),
        client_config,
    )
    .await?;
    let negotiated = four_way_handshake(&mut client).await?;
    info!("client handshake negotiated: {:#?}", negotiated);

    SERVER_HANDSHAKE_COMPLETE.notified().await;

    client.dump_statistics("client");

    Ok(())
}

async fn on_server_connection(server_connection: Connection<BitcoinProtocol>) {
    let mut server_connection = server_connection;
    let negotiated = four_way_handshake(&mut server_connection).await.unwrap();
    info!("server handshake completed: {:#?}", negotiated);
    SERVER_HANDSHAKE_COMPLETE.notify_waiters();
    server_connection.dump_statistics("server");
}

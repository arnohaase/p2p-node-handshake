use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use lazy_static::lazy_static;
use log::{info, LevelFilter};
use simple_logger::SimpleLogger;
use tokio::sync::Notify;
use tokio::sync::oneshot;

use p2p_node_handshake::config::Config;
use p2p_node_handshake::connection::Connection;
use p2p_node_handshake::error::P2PResult;
use p2p_node_handshake::handshake::handshake;
use p2p_node_handshake::message::{BitcoinVersion, Services};
use p2p_node_handshake::server::listen;

lazy_static! {
    static ref SERVER_HANDSHAKE_COMPLETE: Arc<Notify> = Arc::new(Notify::new());
}

#[tokio::test]
async fn test_client_server() -> P2PResult<()>{
    SimpleLogger::new()
        .with_level(LevelFilter::Trace)
        .with_colors(true)
        .init()
        .unwrap();

    let server_config = Arc::new(Config {
        my_address: SocketAddr::from_str("127.0.0.1:18001").unwrap(),
        my_version: BitcoinVersion(60000),
        my_services: Services::NODE_XTHIN,
        payload_size_limit: 10000,
    });

    let (server_running_sender, server_running_receiver) = oneshot::channel();

    tokio::spawn(listen(on_server_connection, server_running_sender, Arc::clone(&server_config)));

    let client_config = Arc::new(Config {
        my_address: SocketAddr::from_str("127.0.0.1:18002").unwrap(),
        my_version: BitcoinVersion(60001),
        my_services: Services::NODE_NETWORK,
        payload_size_limit: 10000,
    });
    server_running_receiver.await.unwrap();
    let mut client = Connection::connect(server_config.my_address.clone(), client_config).await?;
    let negotiated = handshake(&mut client).await?;
    info!("client handshake negotiated: {:#?}", negotiated);

    SERVER_HANDSHAKE_COMPLETE.notified().await;

    Ok(())
}

async fn on_server_connection(server_connection: Connection) {
    let mut server_connection = server_connection;
    let negotiated = handshake(&mut server_connection).await.unwrap();
    info!("server handshake completed: {:#?}", negotiated);
    SERVER_HANDSHAKE_COMPLETE.notify_waiters();
}
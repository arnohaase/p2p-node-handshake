use std::future::Future;
use std::sync::Arc;

use log::info;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::config::Config;
use crate::connection::Connection;
use crate::error::P2PResult;

/// This is a bare bones implementation of a server socket accepting socket connections and providing
///  [Connection] instances.
///
/// Its purpose is to allow handshake to work on connections initiated by a peer as well as those
///  initiated locally. Handing connections to a callback is somewhat unwieldy and probably not the
///  best design for a real server implementation, but it gives straightforward access to connections
///  which is this implementation's focus.
///
/// This code does not try to be a robust, production quality server implementation, and it treats
///  aspects like limiting the number of connections, clean shutdown, exponential backoff or
///  verifying that the network address from listener.accept matches the one in P2P messages as
///  out-of-scope.
pub async fn listen<F, Fut>(
    on_connect: F,
    is_running: oneshot::Sender<()>,
    config: Arc<Config>,
) -> P2PResult<()>
where
    F: Fn(Connection) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = Listener::new(on_connect, config).await?;
    is_running.send(()).unwrap();
    listener.do_listen().await?;
    Ok(())
}

struct Listener<F: Fn(Connection) -> Fut, Fut: Future<Output = ()> + Send + 'static> {
    listener: TcpListener,
    on_connect: F,
    config: Arc<Config>,
}

impl<F: Fn(Connection) -> Fut, Fut: Future<Output = ()> + Send + 'static> Listener<F, Fut> {
    async fn new(on_connect: F, config: Arc<Config>) -> P2PResult<Listener<F, Fut>> {
        info!("listening for connections on {}", config.my_address);
        Ok(Listener {
            listener: TcpListener::bind(config.my_address).await?,
            on_connect,
            config,
        })
    }

    async fn do_listen(&self) -> P2PResult<()> {
        loop {
            let (socket, peer_addr) = self.listener.accept().await?;
            let connection = Connection::new(socket, peer_addr, Arc::clone(&self.config));
            tokio::spawn((self.on_connect)(connection));
        }
    }
}

impl<F: Fn(Connection) -> Fut, Fut: Future<Output = ()> + Send + 'static> Drop
    for Listener<F, Fut>
{
    fn drop(&mut self) {
        info!("shutting down TCP listener")
    }
}

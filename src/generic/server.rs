use std::future::Future;
use std::sync::Arc;

use log::info;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

use crate::generic::connection::Connection;
use crate::generic::protocol::{P2PConfig, P2PProtocol};

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
pub async fn listen<P, F, Fut>(
    on_connect: F,
    is_running: oneshot::Sender<()>,
    config: Arc<P::Config>,
) -> Result<(), P::Error>
where
    P: P2PProtocol,
    F: Fn(Connection<P>) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = Listener::new(on_connect, config).await?;
    is_running.send(()).unwrap();
    listener.do_listen().await?;
    Ok(())
}

struct Listener<F: Fn(Connection<P>) -> Fut, Fut: Future<Output = ()> + Send + 'static, P: P2PProtocol> {
    listener: TcpListener,
    on_connect: F,
    config: Arc<P::Config>,
}

impl<F: Fn(Connection<P>) -> Fut, Fut: Future<Output = ()> + Send + 'static, P: P2PProtocol> Listener<F, Fut, P> {
    async fn new(on_connect: F, config: Arc<P::Config>) -> Result<Listener<F, Fut, P>, P::Error> {
        info!("listening for connections on {}", config.generic_config().my_address);
        Ok(Listener {
            listener: TcpListener::bind(config.generic_config().my_address).await?,
            on_connect,
            config,
        })
    }

    async fn do_listen(&self) -> Result<(), P::Error> {
        loop {
            let (socket, peer_addr) = self.listener.accept().await?;
            let connection = Connection::new(socket, peer_addr, Arc::clone(&self.config));
            tokio::spawn((self.on_connect)(connection));
        }
    }
}

impl<F: Fn(Connection<P>) -> Fut, Fut: Future<Output = ()> + Send + 'static, P: P2PProtocol> Drop
    for Listener<F, Fut, P>
{
    fn drop(&mut self) {
        info!("shutting down TCP listener")
    }
}

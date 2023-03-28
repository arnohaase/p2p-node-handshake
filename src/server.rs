use std::future::Future;
use log::info;
use tokio::net::{TcpListener, ToSocketAddrs};

use crate::connection::Connection;
use crate::error::P2PResult;

/// This is a bare bones implementation of a server socket accepting socket connections and providing
///  [Connection] instances.
///
/// Its purpose is to allow handshake to work on connections initiated by a peer as well as those
///  initiated locally.
///
/// It does not try to be a robust, production quality server implementation, and it treats
///  aspects like limiting the number of connections, clean shutdown, exponential backoff or
///  verifying that the network address from listener.accept matches the one in P2P messages as
///  out-of-scope.
pub async fn listen<F, Fut>(addr: impl ToSocketAddrs, on_connect: F, shutdown: impl Future) -> P2PResult<()>
where
    F: Fn(Connection) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let listener = Listener::new(addr, on_connect).await?;
    tokio::select! {
        _ = listener.do_listen() => { },
        _ = shutdown => { }
    }
    Ok(())
}

struct Listener<
    F: Fn(Connection) -> Fut,
    Fut: Future<Output=()> + Send + 'static,
>  {
    listener: TcpListener,
    on_connect: F
}

impl<
    F: Fn(Connection) -> Fut,
    Fut: Future<Output=()> + Send + 'static,
> Listener<F, Fut> {
    async fn new(addr: impl ToSocketAddrs, on_connect: F) -> P2PResult<Listener<F, Fut>> {
        info!("listening for connections");
        Ok(Listener {
            listener: TcpListener::bind(addr).await?,
            on_connect,
        })
    }

    async fn do_listen(&self) -> P2PResult<()> {
        loop {
            let (socket,_) = self.listener.accept().await?;
            let connection = Connection::new(socket);
            tokio::spawn((self.on_connect)(connection));
        }
    }
}

impl<
    F: Fn(Connection) -> Fut,
    Fut: Future<Output=()> + Send + 'static,
> Drop for Listener<F, Fut> {
    fn drop(&mut self) {
        info!("shutting down TCP listener")
    }
}


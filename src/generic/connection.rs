use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use log::{debug, error, trace, warn};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::generic::protocol::{P2PConfig, P2PError, P2PMessage, P2PProtocol};

/// This is the wrapper for a socket connection to a peer. It manages buffers (allowing buffer
///  reuse), and provides an API at the protocol message level.
///
/// Connections can be created by connecting to a peer, or by spawning when a peer connects to a
///  local listening socket. The data structure is identical regardless of the connection's origin.
pub struct Connection<P: P2PProtocol> {
    socket: TcpStream,
    read_buffer: BytesMut,
    write_buffer: BytesMut,
    /// for debug / logging purposes, and also available to protocol code where the target node's
    ///  is part of a message
    peer_address: SocketAddr,
    config: Arc<P::Config>, //TODO documentation this is passed around because it is fixed
    num_messages_sent: u64,
    num_messages_received: u64,
    pd: PhantomData<P>,
    /// For robustness - if calling code ignores errors (especially when sending messages),
    ///  the write buffer can grow in an unbounded way. This flag is a safeguard against that.
    is_broken: bool,
}
impl <P: P2PProtocol> Connection<P> {
    /// Convenience factory
    pub fn new(socket: TcpStream, peer_address: SocketAddr, config: Arc<P::Config>) -> Connection<P> {
        Connection {
            socket,
            read_buffer: BytesMut::with_capacity(config.generic_config().read_buffer_capacity),
            write_buffer: BytesMut::with_capacity(config.generic_config().write_buffer_capacity),
            peer_address,
            config,
            pd: Default::default(),
            num_messages_sent: 0,
            num_messages_received: 0,
            is_broken: false,
        }
    }

    /// For when the peer's address is part of a message
    pub fn peer_address(&self) -> &SocketAddr {
        &self.peer_address
    }
    /// To make the configuration available. It's immutable, and the connection needs access to
    ///  it anyway, so there's no point in passing it around or storing it redundantly.
    pub fn config(&self) -> &P::Config {
        self.config.as_ref()
    }

    /// Connect to a peer at a known address
    pub async fn connect(addr: SocketAddr, config: Arc<P::Config>) -> Result<Connection<P>, P::Error> {
        debug!("connecting to {}", addr);
        let socket = TcpStream::connect(addr).await?;
        Ok(Connection::new(socket, addr, config))
    }

    /// Return the next available message - the function is async, so this is non-blocking.
    ///
    /// `Ok(None)` means that the connection was closed gracefully.
    /// `Err(_)` leaves the connection in a potentially inconsistent state, making it illegal to
    ///   use for sending or receiving messages.
    pub async fn receive(&mut self) -> Result<Option<P::Message>, P::Error> {
        if self.is_broken {
            error!("This connection with {} is broken (see log for details). Trying to receive \
            messages on it is a bug, please fix your code to reconnect after an error.",
                self.peer_address,
            );
        }

        match self._receive().await {
            Ok(msg) => Ok(msg),
            Err(e) => {
                self.is_broken = true;
                Err(e)
            }
        }
    }

    /// This is a separate method because `try` is still unstable
    async fn _receive(&mut self) -> Result<Option<P::Message>, P::Error> {
        loop {
            match self.parse_message() {
                Ok(Some(msg)) => return Ok(Some(msg)),
                Ok(None) => {
                    if 0 == self.socket.read_buf(&mut self.read_buffer).await? {
                        // 'eof', i.e. connection closed
                        if self.read_buffer.is_empty() {
                            return Ok(None);
                        } else {
                            return Err(P::Error::connection_reset_by_peer());
                        }
                    }
                }
                Err(e) => {
                    warn!("received suspicions message from {} - marking the invalid: {}",
                        self.peer_address,
                        e,
                    );
                    return Err(e);
                }
            }
        }
    }

    /// parse a message that is in the buffer, if any. If it returns an error, that means that
    ///  the message (or message part) is considered potentially dangerous, and the connection
    ///  should be discarded.
    fn parse_message(&mut self) -> Result<Option<P::Message>, P::Error> {
        while P::Message::has_complete_message(self.read_buffer.as_ref(), self.config.as_ref())? {
            self.num_messages_received += 1;
            if let Some(message) = P::Message::de_ser(&mut self.read_buffer, self.config.as_ref()) {
                trace!("receiving message from {}: {:?}", self.peer_address, message);
                return Ok(Some(message));
            } else {
                trace!("receiving unknown message from {}, skipping", self.peer_address);
            }
        }
        Ok(None)
    }

    /// Send a message. The function is async, taking care of network back pressure.
    ///
    /// If the function returns an error, the connection is in a potentially inconsistent state
    ///  and is illegal to use for sending or receiving messages.
    pub async fn send(&mut self, message: &P::Message) -> Result<(), P::Error> {
        trace!("sending message to {}: {:?}", self.peer_address, message);
        if self.is_broken {
            error!("This connection with {} is broken, see log for details. Trying to send messages \
            over this connection is a bug, please fix your code to reconnect after an error.",
                self.peer_address);
            return Err(P::Error::connection_reset_by_peer());
        }

        message.ser(&mut self.write_buffer, self.config.as_ref());
        if let Err(e) = self.socket.write_all_buf(&mut self.write_buffer).await {
            self.is_broken = true;
            return Err(e.into());
        }
        self.num_messages_sent += 1;
        Ok(())
    }

    /// A debugging aid
    pub fn dump_statistics(&self, connection_name: &str) {
        debug!("connection statistics for {}: {} msg sent, {} msg received, read buffer: {}/{}, write_buffer: {}/{}",
            connection_name,
            self.num_messages_sent,
            self.num_messages_received,
            self.read_buffer.len(),
            self.read_buffer.capacity(),
            self.write_buffer.len(),
            self.write_buffer.capacity(),
        )
    }
}

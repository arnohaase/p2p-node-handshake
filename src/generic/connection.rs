use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use log::{debug, error, trace};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::generic::protocol::{P2PConfig, P2PError, P2PMessage, P2PProtocol};

pub struct Connection<P: P2PProtocol> {
    socket: TcpStream,
    read_buffer: BytesMut,
    write_buffer: BytesMut,
    peer_address: SocketAddr,
    config: Arc<P::Config>, //TODO documentation this is passed around because it is fixed
    num_sent: u64,
    num_received: u64,
    pd: PhantomData<P>,
    /// For robustness - if calling code ignores errors (especially when sending messages),
    ///  the write buffer can grow in an unbounded way. This flag is a safeguard against that.
    is_broken: bool,
}
impl <P: P2PProtocol> Connection<P> {
    pub fn new(socket: TcpStream, peer_address: SocketAddr, config: Arc<P::Config>) -> Connection<P> {
        Connection {
            socket,
            read_buffer: BytesMut::with_capacity(config.generic_config().read_buffer_capacity),
            write_buffer: BytesMut::with_capacity(config.generic_config().write_buffer_capacity),
            peer_address,
            config,
            pd: Default::default(),
            num_sent: 0,
            num_received: 0,
            is_broken: false,
        }
    }

    pub fn peer_address(&self) -> &SocketAddr {
        &self.peer_address
    }
    pub fn config(&self) -> &P::Config {
        self.config.as_ref()
    }

    pub async fn connect(addr: SocketAddr, config: Arc<P::Config>) -> Result<Connection<P>, P::Error> {
        debug!("connecting to {}", addr);
        let socket = TcpStream::connect(addr).await?;
        Ok(Connection::new(socket, addr, config))
    }

    pub async fn receive(&mut self) -> Result<Option<P::Message>, P::Error> {
        loop {
            if let Some(message) = self.parse_message()? {
                return Ok(Some(message));
            }

            if 0 == self.socket.read_buf(&mut self.read_buffer).await? {
                // 'eof', i.e. connection closed
                if self.read_buffer.is_empty() {
                    return Ok(None);
                } else {
                    return Err(P::Error::connection_reset_by_peer());
                }
            }
        }
    }

    fn parse_message(&mut self) -> Result<Option<P::Message>, P::Error> {
        while P::Message::has_complete_message(self.read_buffer.as_ref(), self.config.as_ref())? {
            self.num_received += 1;
            if let Some(message) = P::Message::parse_message(&mut self.read_buffer, self.config.as_ref()) {
                trace!("receiving message from {}: {:?}", self.peer_address, message);
                return Ok(Some(message));
            } else {
                trace!("receiving unknown message from {}, skipping", self.peer_address);
            }
        }
        Ok(None)
    }

    ///TODO an error may leave the connection in an inconsistent state - caller should clean up
    pub async fn send(&mut self, message: &P::Message) -> Result<(), P::Error> {
        trace!("sending message to {}: {:?}", self.peer_address, message);
        if self.is_broken {
            error!("A previoius network error sending data to {} left the connection in a \
            potentially inconsistent state. Trying to send messages over this connection is\
            a bug, please fix your code to reconnect after a send error", self.peer_address);
            return Err(P::Error::connection_reset_by_peer());
        }

        message.ser(&mut self.write_buffer, self.config.as_ref());
        if let Err(e) = self.socket.write_all_buf(&mut self.write_buffer).await {
            self.is_broken = true;
            return Err(e.into());
        }
        self.num_sent += 1;
        Ok(())
    }

    pub fn dump_statistics(&self, connection_name: &str) {
        debug!("connection statistics for {}: {} msg sent, {} msg received, read buffer: {}/{}, write_buffer: {}/{}",
            connection_name,
            self.num_sent,
            self.num_received,
            self.read_buffer.len(),
            self.read_buffer.capacity(),
            self.write_buffer.len(),
            self.write_buffer.capacity(),
        )
    }
}

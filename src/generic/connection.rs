use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use log::debug;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::generic::protocol::{P2PConfig, P2PError, P2PMessage, P2PProtocol};

pub struct Connection<P: P2PProtocol> {
    socket: TcpStream,
    read_buffer: BytesMut,
    write_buffer: BytesMut,
    pub peer_address: SocketAddr,
    pub config: Arc<P::Config>, //TODO documentation this is passed around because it is fixed
    pd: PhantomData<P>,
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
        }
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
            if let Some(message) = P::Message::parse_message(&mut self.read_buffer, self.config.as_ref()) {
                return Ok(Some(message));
            }
        }
        Ok(None)
    }

    ///TODO an error may leave the connection in an inconsistent state - caller should clean up
    pub async fn send(&mut self, message: &P::Message) -> Result<(), P::Error> {
        message.ser(&mut self.write_buffer, self.config.as_ref());
        self.socket.write_all_buf(&mut self.write_buffer).await?;
        Ok(())
    }
}

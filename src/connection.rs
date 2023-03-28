use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use crate::config::Config;

use crate::error::{P2PError, P2PResult};
use crate::message::Message;

pub struct Connection {
    socket: TcpStream,
    read_buffer: BytesMut,
    write_buffer: BytesMut,
    pub peer_address: SocketAddr,
    pub config: Arc<Config>, //TODO documentation this is passed around because it is fixed
}
impl Connection { //TODO test
    pub fn new(socket: TcpStream, peer_address: SocketAddr, config: Arc<Config>) -> Connection {
        Connection {
            socket: socket,
            read_buffer: BytesMut::with_capacity(0x10000), //TODO configurable
            write_buffer: BytesMut::new(),
            peer_address,
            config,
        }
    }

    pub async fn connect(addr: SocketAddr, config: Arc<Config>) -> P2PResult<Connection> {
        let socket = TcpStream::connect(addr).await?;
        Ok(Connection::new(socket, addr, config))
    }

    pub async fn receive(&mut self) -> P2PResult<Option<Message>> {
        //TODO mark connection as broken on I/O error

        loop {
            if let Some(message) = self.parse_message()? {
                return Ok(Some(message));
            }

            if 0 == self.socket.read_buf(&mut self.read_buffer).await? {
                // 'eof', i.e. connection closed
                if self.read_buffer.is_empty() {
                    return Ok(None);
                }
                else {
                    return Err(P2PError::ConnectionResetByPeer);
                }
            }
        }
    }

    fn parse_message(&mut self) -> P2PResult<Option<Message>> {
        while Message::has_complete_message(self.read_buffer.as_ref(), self.config.as_ref())? {
            if let Some(message) = Message::parse(&mut self.read_buffer) {
                return Ok(Some(message));
            }
        }
        Ok(None)
    }

    pub async fn send(&mut self, message: &Message) -> P2PResult<()> {
        message.ser(&mut self.write_buffer);
        self.socket.write_all_buf(&mut self.write_buffer).await?;
        //TODO mark connection as broken on I/O error
        Ok(())
    }
}

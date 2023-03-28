use bytes::BytesMut;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, ToSocketAddrs};
use crate::error::{P2PError, P2PResult};

use crate::message::Message;

pub struct Connection {
    socket: TcpStream,
    read_buffer: BytesMut,
    write_buffer: BytesMut,
}
impl Connection { //TODO test
    pub fn new(socket: TcpStream) -> Connection {
        Connection {
            socket: socket,
            read_buffer: BytesMut::with_capacity(0x10000), //TODO configurable
            write_buffer: BytesMut::new(),
        }
    }

    pub async fn connect(addr: impl ToSocketAddrs) -> P2PResult<Connection> {
        let socket = TcpStream::connect(addr).await?;
        Ok(Connection::new(socket))
    }

    pub async fn read_message(&mut self) -> P2PResult<Option<Message>> {
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
        while Message::has_complete_message(self.read_buffer.as_ref())? {
            if let Some(message) = Message::parse(&mut self.read_buffer) {
                return Ok(Some(message));
            }
        }
        Ok(None)
    }

    pub async fn write_message(&mut self, message: &Message) -> P2PResult<()> {
        message.ser(&mut self.write_buffer);
        self.socket.write_all_buf(&mut self.write_buffer).await?;
        //TODO mark connection as broken on I/O error
        Ok(())
    }
}

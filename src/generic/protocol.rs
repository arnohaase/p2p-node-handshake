use std::fmt::{Debug, Display};
use std::net::SocketAddr;

use bytes::BytesMut;

pub trait P2PProtocol: Sized {
    type Config: P2PConfig;
    type Error: P2PError;
    type Message: P2PMessage<Self>;
}

pub trait P2PError: From<std::io::Error> + Debug + Display {
    fn connection_reset_by_peer() -> Self;
}

pub trait P2PConfig {
    fn generic_config(&self) -> &GenericP2PConfig;
}

pub struct GenericP2PConfig {
    pub my_address: SocketAddr,
    pub read_buffer_capacity: usize,
    pub write_buffer_capacity: usize,
}
impl GenericP2PConfig {
    pub fn new(my_address: SocketAddr) -> GenericP2PConfig {
        GenericP2PConfig {
            my_address,
            read_buffer_capacity: Self::DEFAULT_BUFFER_CAPACITY,
            write_buffer_capacity: Self::DEFAULT_BUFFER_CAPACITY,
        }
    }

    pub const DEFAULT_BUFFER_CAPACITY: usize = 16384;
}

pub trait P2PMessage<P: P2PProtocol>: Sized + Debug {
    fn has_complete_message(buf: &[u8], config: &P::Config) -> Result<bool, P::Error>;
    fn parse_message(buf: &mut BytesMut, config: &P::Config) -> Option<Self>;
    fn ser(&self, buf: &mut BytesMut, config: &P::Config);
}

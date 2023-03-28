use std::net::SocketAddr;

use crate::types::{BitcoinNetworkId, BitcoinVersion, Services};

pub struct Config {
    pub my_address: SocketAddr,
    pub my_version: BitcoinVersion,
    pub my_bitcoin_network: BitcoinNetworkId,
    pub my_services: Services,
    pub payload_size_limit: usize,
    pub read_buffer_capacity: usize,
    pub write_buffer_capacity: usize,
}
impl Config {
    pub const DEFAULT_PAYLOAD_SIZE_LIMIT: usize = 10000;
    pub const DEFAULT_BUFFER_CAPACITY: usize = 16384;
}

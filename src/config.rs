use std::net::SocketAddr;
use crate::message::{Services, BitcoinVersion, BitcoinNetworkId};

pub struct Config {
    pub my_address: SocketAddr,
    pub my_version: BitcoinVersion,
    pub my_bitcoin_network: BitcoinNetworkId,
    pub my_services: Services,
    pub payload_size_limit: usize,
}
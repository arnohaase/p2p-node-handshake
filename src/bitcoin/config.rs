use crate::bitcoin::types::*;
use crate::generic::protocol::{GenericP2PConfig, P2PConfig};

pub struct BitcoinConfig {
    pub generic_config: GenericP2PConfig,
    pub my_version: BitcoinVersion,
    pub my_bitcoin_network: BitcoinNetworkId,
    pub my_services: Services,
    pub payload_size_limit: usize,
}

impl BitcoinConfig {
    pub const DEFAULT_PAYLOAD_SIZE_LIMIT: usize = 10000;
}

impl P2PConfig for BitcoinConfig {
    fn generic_config(&self) -> &GenericP2PConfig {
        &self.generic_config
    }
}
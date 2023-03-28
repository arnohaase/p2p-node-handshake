use crate::bitcoin::types::*;
use crate::generic::protocol::{GenericP2PConfig, P2PConfig};

/// Configuration options for Bitcoin connection and handshake
pub struct BitcoinConfig {
    /// The non-Bitcoin specific part of the configuration
    pub generic_config: GenericP2PConfig,
    /// The Bitcoin 'network' (Main, Test, ...) we are connecting on. Only nodes on the
    ///  same network can connect.
    pub my_bitcoin_network: BitcoinNetworkId,
    /// Bitcoin protocol version supported by this node. For initial handshake, this is
    ///  largely pass-through data without semantics, but some messages are extended for
    ///  versions above a certain value.
    pub my_version: BitcoinVersion,
    /// A set of features that this node offers. This is sent to peers during initial handshake,
    ///  and they are likely to send messages depending on the services we offer. As long as we
    ///  just do initial handshake, the safe value to use is `Services::empty()`.
    pub my_services: Services,
    /// This threshold is a robustness feature to safeguard against heap consumption based
    ///  DoS. Since messages are self-describing (with a 32 bit value for payload length), a
    ///  manipulated peer could send formally valid messages with Gigabytes of payload which
    ///  could bring our node down if we read them into memory before discarding them.
    ///
    /// This threshold discards messages that are bigger than expected, treating them as a DoS
    ///  attack and marking the connection as broken.
    ///
    /// This threshold is a trade-off between robustness and the ability to skip future messages
    ///  that may be bigger than current ones.
    pub payload_size_limit: usize,
}

impl BitcoinConfig {
    /// Sane default value for payload size limit
    pub const DEFAULT_PAYLOAD_SIZE_LIMIT: usize = 10000;
}

impl P2PConfig for BitcoinConfig {
    fn generic_config(&self) -> &GenericP2PConfig {
        &self.generic_config
    }
}

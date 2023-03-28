use std::time::{SystemTime, UNIX_EPOCH};

use bitflags::bitflags;
use log::warn;

/// An identifier for one of the well-known Bitcoin networks. Peers must be on the same network.
#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub enum BitcoinNetworkId {
    /// main
    Main,
    /// testnet/regtest
    TestNetRegTest,
    /// testnet3
    TestNet3,
    /// signet(default)
    SigNet,
    /// namecoin
    NameCoin,
}
impl BitcoinNetworkId {
    const MAIN: u32 = 0xD9B4BEF9;
    const TESTNET_REGTEST: u32 = 0xDAB5BFFA;
    const TESTNET3: u32 = 0x0709110B;
    const SIGNET: u32 = 0x40CF030A;
    const NAMECOIN: u32 = 0xFEB4BEF9;

    /// return the network ID's magic number as its network representation
    pub fn ser(&self) -> u32 {
        match self {
            BitcoinNetworkId::Main => Self::MAIN,
            BitcoinNetworkId::TestNetRegTest => Self::TESTNET_REGTEST,
            BitcoinNetworkId::TestNet3 => Self::TESTNET3,
            BitcoinNetworkId::SigNet => Self::SIGNET,
            BitcoinNetworkId::NameCoin => Self::NAMECOIN,
        }
    }

    /// translate a magic number to the Bitcoin network ID, or None if it is none of the
    ///  well-known numbers
    pub fn de_ser(raw: u32) -> Option<Self> {
        match raw {
            Self::MAIN => Some(Self::Main),
            Self::TESTNET_REGTEST => Some(Self::TestNetRegTest),
            Self::TESTNET3 => Some(Self::TestNet3),
            Self::SIGNET => Some(Self::SigNet),
            Self::NAMECOIN => Some(Self::NameCoin),
            _ => None,
        }
    }
}

bitflags! {
    /// A bitmask representing a combination of services offered by a node - see the Bitcoin
    ///  protocol documentation for details.
    ///
    /// Services are communicated during handshake, but their semantics are out of scope for this
    ///  project - using `Services::empty()` is the safest bet for nodes that do nothing but handshake.
    #[derive(Eq, PartialEq, Debug, Clone, Copy)]
    pub struct Services: u64 {
        /// see Bitcoin protocol documentation for details
        const NODE_NETWORK = 1;
        /// see Bitcoin protocol documentation for details
        const NODE_GETUTXO = 2;
        /// see Bitcoin protocol documentation for details
        const NODE_BLOOM = 4;
        /// see Bitcoin protocol documentation for details
        const NODE_WITNESS = 8;
        /// see Bitcoin protocol documentation for details
        const NODE_XTHIN = 16;
        /// see Bitcoin protocol documentation for details
        const NODE_COMPACT_FILTERS = 64;
        /// see Bitcoin protocol documentation for details
        const NODE_NETWORK_LIMITED = 1024;
    }
}

/// Bitcoin protocol version number.
#[derive(Eq, PartialEq, Ord, PartialOrd, Clone, Copy, Debug)]
pub struct BitcoinVersion(pub u32);

impl From<BitcoinVersion> for u32 {
    fn from(value: BitcoinVersion) -> Self {
        value.0
    }
}
impl From<&BitcoinVersion> for u32 {
    fn from(value: &BitcoinVersion) -> Self {
        value.0
    }
}

/// Timestamp, encoding seconds since UNIX_EPOCH.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Timestamp(i64);
impl Timestamp {
    /// Current wall clock time
    pub fn now() -> Timestamp {
        let seconds = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => match d.as_secs().try_into() {
                Ok(s) => s,
                Err(_) => {
                    warn!("system clock indicates time before Unix epoch, defaulting to Unix epoch exactly");
                    0
                }
            },
            Err(e) => {
                warn!("system time error - system clock before Unix epoch? Defaulting to Unix epoch exactly: {:?}", e);
                0
            }
        };
        Timestamp(seconds)
    }

    /// get an Instant's wire representation
    pub fn ser(&self) -> i64 {
        self.0
    }

    /// create an Instant from its wire representation
    pub fn de_ser(raw: i64) -> Self {
        Timestamp(raw)
    }
}

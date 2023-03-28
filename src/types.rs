use std::time::{SystemTime, UNIX_EPOCH};

use bitflags::bitflags;
use log::warn;

#[derive(Eq, PartialEq, Clone, Copy, Debug)]
pub enum BitcoinNetworkId {
    Main,
    TestNetRegTest,
    TestNet3,
    SigNet,
    NameCoin,
}
impl BitcoinNetworkId {
    const MAIN: u32 = 0xD9B4BEF9;
    const TESTNET_REGTEST: u32 = 0xDAB5BFFA;
    const TESTNET3: u32 = 0x0709110B;
    const SIGNET: u32 = 0x40CF030A;
    const NAMECOIN: u32 = 0xFEB4BEF9;

    pub fn ser(&self) -> u32 {
        match self {
            BitcoinNetworkId::Main => Self::MAIN,
            BitcoinNetworkId::TestNetRegTest => Self::TESTNET_REGTEST,
            BitcoinNetworkId::TestNet3 => Self::TESTNET3,
            BitcoinNetworkId::SigNet => Self::SIGNET,
            BitcoinNetworkId::NameCoin => Self::NAMECOIN,
        }
    }

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
    #[derive(Eq, PartialEq, Debug, Clone, Copy)]
    pub struct Services: u64 {
        const NODE_NETWORK = 1;
        const NODE_GETUTXO = 2;
        const NODE_BLOOM = 4;
        const NODE_WITNESS = 8;
        const NODE_XTHIN = 16;
        const NODE_COMPACT_FILTERS = 64;
        const NODE_NETWORK_LIMITED = 1024;
    }
}

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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Timestamp(i64);
impl Timestamp {
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

    pub fn ser(&self) -> i64 {
        self.0
    }

    pub fn de_ser(raw: i64) -> Self {
        Timestamp(raw)
    }
}

pub enum Command {
    Version,
    VerAck,
}
impl Command {
    pub fn de(id: &[u8]) -> Option<Command> {
        match id {
            COMMAND_VERSION => Some(Self::Version),
            COMMAND_VERACK => Some(Self::VerAck),
            _ => None,
        }
    }
}

pub type CommandId = [u8; 12];

pub const COMMAND_VERSION: &[u8] = b"version\0\0\0\0\0";
pub const COMMAND_VERACK: &[u8] = b"verack\0\0\0\0\0\0";

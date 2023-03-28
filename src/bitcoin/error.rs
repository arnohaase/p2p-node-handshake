use thiserror::Error;
use crate::generic::protocol::P2PError;

pub type BitcoinResult<T> = Result<T, BitcoinError>;

#[derive(Debug, Error)]
pub enum BitcoinError {
    #[error("The message is way bigger than any legal message as specified in the protocol. This is \
    treated as a protocol violation and potential DoS attack, causing the entire connection to be dropped.")]
    MessageTooBig,
    #[error(
        "The remote magic number {remote:#08x} does not match the local magic number {local:#08x}"
    )]
    MagicMismatch { local: u32, remote: u32 },
    #[error("Connection reset by peer")]
    ConnectionResetByPeer,
    #[error("I/O error: {0}")]
    Io(std::io::Error),
}

impl P2PError for BitcoinError {
    fn connection_reset_by_peer() -> Self {
        BitcoinError::ConnectionResetByPeer
    }
}
impl From<std::io::Error> for BitcoinError {
    fn from(value: std::io::Error) -> Self {
        BitcoinError::Io(value)
    }
}


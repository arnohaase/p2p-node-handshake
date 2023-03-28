use crate::generic::protocol::P2PError;
use thiserror::Error;

/// Convenience return type for functions that can fail with a [BitcoinError]
pub type BitcoinResult<T> = Result<T, BitcoinError>;

/// Potential errors when working with the Bitcoin protocol.
///
/// Note that generic error handling is embedded into this enum by implementing [P2PError].
#[derive(Debug, Error)]
pub enum BitcoinError {
    /// Payload threshold exceeded
    #[error("The message is way bigger than any legal message as specified in the protocol. This is \
    treated as a protocol violation and potential DoS attack, causing the entire connection to be dropped.")]
    MessageTooBig,

    /// A received message has a different magic number (i.e. a different Bitcoin network) than
    ///  is configured for us
    #[error(
        "The remote magic number {remote:#08x} does not match the local magic number {local:#08x}"
    )]
    MagicMismatch {
        /// local magic number
        local: u32,
        /// remote magic number
        remote: u32,
    },

    /// Generic network error: connection closed unexpectedly
    #[error("Connection reset by peer")]
    ConnectionResetByPeer,

    /// Generic wrapper for I/O errors
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

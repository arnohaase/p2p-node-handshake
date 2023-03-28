use thiserror::Error;

pub type P2PResult<T> = Result<T, P2PError>;

#[derive(Debug, Error)]
pub enum P2PError {
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

impl From<std::io::Error> for P2PError {
    fn from(value: std::io::Error) -> Self {
        P2PError::Io(value)
    }
}

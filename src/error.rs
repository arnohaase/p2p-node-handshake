
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum P2PError {
    MessageTooBig,
    MagicMismatch,
}
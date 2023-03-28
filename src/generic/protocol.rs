use std::fmt::{Debug, Display};
use std::net::SocketAddr;

use bytes::BytesMut;

/// This abstraction defines what a specific protocol must provide in order to use the generic
///  connection and handshake handling.
pub trait P2PProtocol: Sized {
    /// The specific protocol's configuration data. It needs to contain [GenericP2PConfig]
    ///  data, which is ensured by the type bound.
    type Config: P2PConfig;
    /// The protocol specific error type. It needs to be able to work with the generic code,
    ///  hence the type bound.
    type Error: P2PError;
    /// The protocol specific message type.
    type Message: P2PMessage<Self>;
}

/// Required functionality on an error type to support generic code's needs.
pub trait P2PError: From<std::io::Error> + Debug + Display {
    /// factory for 'connection reset by peer' errors
    fn connection_reset_by_peer() -> Self;
}

/// A type bound for configuration data, giving generic code to its configuration
pub trait P2PConfig {
    /// Retrieve generic config data
    fn generic_config(&self) -> &GenericP2PConfig;
}

/// Configuration data required by generic code
pub struct GenericP2PConfig {
    /// This node's network address
    pub my_address: SocketAddr,
    /// Initial read buffer capacity
    pub read_buffer_capacity: usize,
    /// Initial write buffer capacity
    pub write_buffer_capacity: usize,
}
impl GenericP2PConfig {
    /// Convenience factory
    pub fn new(my_address: SocketAddr) -> GenericP2PConfig {
        GenericP2PConfig {
            my_address,
            read_buffer_capacity: Self::DEFAULT_BUFFER_CAPACITY,
            write_buffer_capacity: Self::DEFAULT_BUFFER_CAPACITY,
        }
    }

    /// A sane default value for buffer capacity
    pub const DEFAULT_BUFFER_CAPACITY: usize = 16384;
}

/// Required API on protocol specific messages to allow usage by generic code
pub trait P2PMessage<P: P2PProtocol>: Sized + Debug {
    /// Check (efficiently) if a buffer contains a complete message - messages can be split
    ///  across several network packets, so the buffer may hold only a partial message as yet.
    ///  This is a performance optimization because checking for completeness of a message can
    ///  typically be done significantly more efficiently than trying to parse the message and
    ///  failing on the wqy.
    ///
    /// This function has a second, more subtle purpose: It can check for malicious (though
    ///  technically valid) messages, returning an error if it categorizes a message that way.
    ///  A typical example is self-describing variable-length messages with huge sizes
    ///  where all valid messages are small.
    fn has_complete_message(buf: &[u8], config: &P::Config) -> Result<bool, P::Error>;

    /// Parse a message from a buffer. This function is only called if `has_complete_message`
    ///  returned `Ok(true)` on the same buffer, so the message's data is guaranteed to be
    ///  available.
    ///
    /// NB: This function can not return an error - if a message is inconsistent (or unknown
    ///  or whatever) it is consumed completely, potentially logged, and then ignored by returning
    ///  `None`.
    fn de_ser(buf: &mut BytesMut, config: &P::Config) -> Option<Self>;

    /// Serialize a message into a given buffer. `BytesBuf` grows dynamically if needed (which
    ///  the protocol implementation ensures is bounded for bounded-length messages), so there
    ///  is no failure mode for this function.
    fn ser(&self, buf: &mut BytesMut, config: &P::Config);
}

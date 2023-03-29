use log::debug;
use std::fmt::Debug;
use tokio::sync::Mutex;

use crate::generic::connection::Connection;
use crate::generic::protocol::{P2PError, P2PProtocol};

/// This is a generic implementation of a four-way handshake.
///
/// It consists of both nodes sending initial 'version' messages, and replying with 'ack' messages.
///  (The messages in the actual protocols will typically have different names.) This implementation
///  assumes that the 'version' messages are sent independently of each other, and that each 'ack'
///  message only depends on the 'version' message it acknowledges.
///
/// This generic four-way handshake implementation may be somewhat over-engineered for the task
///  of implementing *one* P2P handshake, and it is unproven that it actually supports other
///  protocols, but it does capture the essence of the handshake, and it fits in with the
///  focus on versatility and showcasing of idiomatic Rust.
pub trait FourWayHandshakeProtocol: P2PProtocol {
    /// This is the data - based on the other node's messages - that is negotiated as the result of
    ///  the four-way handshake and available for the application - e.g. protocol version,
    ///  supported features etc.
    type NegotiatedMetaData: Debug;

    /// Data from a 'version' message to keep for sending an 'ack' message, or as input for the
    ///  negotiation result
    type ReceivedVersionExtract;
    /// Data from an 'ack' message to keep as input for the negotiation result
    type ReceivedAckExtract;

    /// factory for creating a (protocol specific) version message for use in the handshake protocol
    fn version_message(connection: &Connection<Self>) -> Self::Message;
    /// factory for creating a (protocol specific) ack message for use in the handshake protocol
    fn ack_message(
        connection: &Connection<Self>,
        version_message: &Self::ReceivedVersionExtract,
    ) -> Self::Message;

    /// Extract the essentials from received version and ack messages, ignoring any other messages
    fn categorize_incoming(message: &Self::Message) -> Option<HandshakeMessageExtract<Self>>;

    /// Combine the received version and ack messages into the 'negotiated' metadata to keep around
    ///  as the result of the handshake
    fn negotiation_result(
        config: &Self::Config,
        version_data: &Self::ReceivedVersionExtract,
        ack_data: &Self::ReceivedAckExtract,
    ) -> Self::NegotiatedMetaData;
}

/// This enum stores 'relevant' parts of the version and ack messages. That makes the data accessible
///  at the generic level (`Message` is just a black box here).
pub enum HandshakeMessageExtract<P: FourWayHandshakeProtocol> {
    /// The essence of a received version message
    Version(P::ReceivedVersionExtract),
    /// The essence of a received ack message
    Ack(P::ReceivedAckExtract),
}

/// Perform a four-way handshake on a given connection, completing when the handshake is done
///  way or another.
///
/// NB: Timeout handling is not part of this API, but client code can add it wrapping the future
///      using `tokio::time::timeout()`. Keeping timeout handling outside the API makes for a
///      clearer and more robust API.
pub async fn four_way_handshake<P: FourWayHandshakeProtocol>(
    connection: &mut Connection<P>,
) -> Result<P::NegotiatedMetaData, P::Error> {
    // Initiate the handshake by sending a 'version' message
    connection.send(&P::version_message(connection)).await?;

    #[allow(clippy::type_complexity)]
    let received_extracts: Mutex<(
        Option<P::ReceivedVersionExtract>,
        Option<P::ReceivedAckExtract>,
    )> = Mutex::new((None, None));

    loop {
        match connection.receive().await? {
            None => return Err(P::Error::connection_reset_by_peer()),
            Some(message) => {
                match P::categorize_incoming(&message) {
                    Some(HandshakeMessageExtract::Version(data)) => {
                        connection.send(&P::ack_message(connection, &data)).await?;

                        let mut lock = received_extracts.lock().await;
                        lock.0 = Some(data);
                    }
                    Some(HandshakeMessageExtract::Ack(data)) => {
                        let mut lock = received_extracts.lock().await;
                        lock.1 = Some(data);
                    }
                    None => {
                        // we ignore other messages during the handshake
                    }
                }
            }
        }

        let lock = received_extracts.lock().await;
        if let (Some(version_extract), Some(ack_extract)) = (&lock.0, &lock.1) {
            let result = P::negotiation_result(connection.config(), version_extract, ack_extract);
            debug!(
                "client-side handshake completed - negotiated meta data is {:?}",
                result
            );
            return Ok(result);
        }
    }
}

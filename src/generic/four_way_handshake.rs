use std::fmt::Debug;
use log::debug;
use tokio::sync::Mutex;

use crate::generic::connection::Connection;
use crate::generic::protocol::P2PProtocol;

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

    type ReceivedVersionExtract;
    type ReceivedAckExtract;

    fn version_message(connection: &Connection<Self>) -> Self::Message;
    fn ack_message(connection: &Connection<Self>, version_message: &Self::ReceivedVersionExtract) -> Self::Message;

    fn categorize_incoming(message: &Self::Message) -> Option<HandshakeMessageExtract<Self>>;

    fn negotiation_result(config: &Self::Config, version_data: &Self::ReceivedVersionExtract, ack_data: &Self::ReceivedAckExtract) -> Self::NegotiatedMetaData;
}

/// This enum stores 'relevant' parts of the version and ack messages. That makes the data accessible
///  at the generic level (`Message` is just a black box here).
pub enum HandshakeMessageExtract<P: FourWayHandshakeProtocol> {
    Version(P::ReceivedVersionExtract),
    Ack(P::ReceivedAckExtract),
}

//TODO documentation - None means connection was closed
//TODO documentation - timeout via decorator
pub async fn four_way_handshake<P: FourWayHandshakeProtocol>(connection: &mut Connection<P>) -> Result<Option<P::NegotiatedMetaData>, P::Error> {
    // Initiate the handshake by sending a 'version' message
    connection
        .send(&P::version_message(&connection))
        .await?;

    let received_extracts: Mutex<(Option<P::ReceivedVersionExtract>, Option<P::ReceivedAckExtract>)> = Mutex::new((None, None));

    loop {
        match connection.receive().await? {
            None => return Ok(None),
            Some(message) => {
                match P::categorize_incoming(&message) {
                    Some(HandshakeMessageExtract::Version(data)) => {
                        connection.send(&P::ack_message(&connection, &data)).await?;

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
            debug!("client-side handshake completed - negotiated meta data is {:?}", result);
            return Ok(Some(result));
        }
    }
}

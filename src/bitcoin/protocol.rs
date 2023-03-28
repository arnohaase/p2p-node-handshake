use crate::bitcoin::config::BitcoinConfig;
use crate::bitcoin::error::BitcoinError;
use crate::bitcoin::message::{BitcoinMessage, NetworkAddressWithoutTimestamp};
use crate::bitcoin::types::{BitcoinVersion, Services, Timestamp};
use crate::generic::connection::Connection;
use crate::generic::four_way_handshake::{FourWayHandshakeProtocol, HandshakeMessageExtract};
use crate::generic::protocol::P2PProtocol;

#[derive(Clone, Debug)]
pub struct BitcoinPeerMetaData {
    pub version: BitcoinVersion,
    pub services: Services,
}

pub struct BitcoinProtocol {}

impl P2PProtocol for BitcoinProtocol {
    type Config = BitcoinConfig;
    type Error = BitcoinError;
    type Message = BitcoinMessage;
}

impl FourWayHandshakeProtocol for BitcoinProtocol {
    type NegotiatedMetaData = BitcoinPeerMetaData;
    type ReceivedVersionExtract = BitcoinPeerMetaData;
    type ReceivedAckExtract = ();

    fn version_message(connection: &Connection<Self>) -> Self::Message {
        BitcoinMessage::Version {
            version: connection.config().my_version,
            services: connection.config().my_services,
            timestamp: Timestamp::now(),
            addr_recv: NetworkAddressWithoutTimestamp::new(
                &connection.peer_address(),
                connection.config(),
            ),
        }
    }

    fn ack_message(_connection: &Connection<Self>, _version_message: &Self::ReceivedVersionExtract) -> Self::Message {
        BitcoinMessage::VerAck
    }

    fn categorize_incoming(message: &Self::Message) -> Option<HandshakeMessageExtract<Self>> {
        match message {
            BitcoinMessage::Version { version, services, .. } => Some(
                HandshakeMessageExtract::Version(BitcoinPeerMetaData {
                    version: *version,
                    services: *services,
                })
            ),
            BitcoinMessage::VerAck => Some(HandshakeMessageExtract::Ack(())),
        }
    }

    fn negotiation_result(_config: &BitcoinConfig, version_data: &BitcoinPeerMetaData, _ack_data: &()) -> BitcoinPeerMetaData {
        version_data.clone()
    }
}
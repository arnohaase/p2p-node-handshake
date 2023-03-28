use std::io::Cursor;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::{Buf, BufMut, BytesMut};
use log::{debug, warn};
use sha2::{Digest, Sha256};

use crate::bitcoin::config::*;
use crate::bitcoin::error::{BitcoinError, BitcoinResult};
use crate::bitcoin::protocol::BitcoinProtocol;
use crate::bitcoin::types::*;
use crate::generic::protocol::P2PMessage;

/// Network address without timestamp - Bitcoin spec specifies a 'timestamp' as part of a network
///  address, everywhere except for Version messages
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NetworkAddressWithoutTimestamp {
    pub services: Services,
    pub addr: IpAddr,
    pub port: u16,
}
impl NetworkAddressWithoutTimestamp {
    pub fn new(peer_addr: &SocketAddr, config: &BitcoinConfig) -> NetworkAddressWithoutTimestamp {
        NetworkAddressWithoutTimestamp {
            services: config.my_services,
            addr: peer_addr.ip(),
            port: peer_addr.port(),
        }
    }
}

const MESSAGE_HEADER_LEN_ON_NETWORK: usize = 4 + 12 + 4 + 4; // magic + command + length + checksum
const MESSAGE_HEADER_OFFS_PAYLOAD_LENGTH: usize = 4 + 12; // magic + command

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum BitcoinMessage {
    Version {
        version: BitcoinVersion,
        services: Services,
        timestamp: Timestamp,
        addr_recv: NetworkAddressWithoutTimestamp,
    },
    VerAck,
}
impl BitcoinMessage {
    fn command_string(&self) -> &'static [u8] {
        match self {
            BitcoinMessage::Version { .. } => COMMAND_VERSION,
            BitcoinMessage::VerAck => COMMAND_VERACK,
        }
    }

    fn payload(&self) -> Vec<u8> {
        //TODO avoid copying?
        match self {
            BitcoinMessage::Version {
                version,
                services,
                timestamp,
                addr_recv,
            } => {
                let mut result = Vec::new();
                (&mut result).put_u32_le(version.into());
                (&mut result).put_u64_le(services.bits());
                (&mut result).put_i64_le(timestamp.ser());
                (&mut result).put_u64_le(addr_recv.services.bits());
                match addr_recv.addr {
                    IpAddr::V4(addr) => {
                        (&mut result).put_bytes(0, 12);
                        (&mut result).put_slice(&addr.octets());
                    }
                    IpAddr::V6(addr) => {
                        (&mut result).put_slice(&addr.octets());
                    }
                }
                (&mut result).put_u16(addr_recv.port);

                (&mut result).put_bytes(0, 26); // addr_from - safe to ignore, most implementations send dummy data
                (&mut result).put_bytes(0, 8); // nonce - not part of the minimum set of fields, treated as out-of-scope
                (&mut result).put_u8(0); // user agent - setting to 'empty'
                (&mut result).put_u32_le(0); // last block received - treated as out-of-scope

                result
            }
            BitcoinMessage::VerAck => vec![],
        }
    }
}

impl P2PMessage<BitcoinProtocol> for BitcoinMessage {
    fn has_complete_message(buf: &[u8], config: &BitcoinConfig) -> BitcoinResult<bool> {
        if buf.len() < MESSAGE_HEADER_LEN_ON_NETWORK {
            return Ok(false);
        }
        let payload_len: usize = (&buf[MESSAGE_HEADER_OFFS_PAYLOAD_LENGTH..])
            .get_u32_le()
            .try_into()
            .expect("<32 bit architecture not supported");
        if payload_len > config.payload_size_limit {
            return Err(BitcoinError::MessageTooBig);
        }
        Ok(buf.len() >= MESSAGE_HEADER_LEN_ON_NETWORK + payload_len)
    }

    /// todo documentation: assumes that the buffer contains an entire message, panicking otherwise
    /// todo  always consumes a message, returning None if the message was not recognized
    fn parse_message(buf: &mut BytesMut, config: &BitcoinConfig) -> Option<Self> {
        let magic = buf.get_u32_le();

        let command_id = &buf[..size_of::<CommandId>()];
        let command = Command::de(command_id);

        buf.advance(size_of::<CommandId>());

        let payload_len: usize = buf
            .get_u32_le()
            .try_into()
            .expect("<32 bit architecture not supported");
        let checksum = buf.get_u32_le();

        // implementation: decouple buffer advancement from payload handling - we want to advance
        //  the buffer's start based on the payload length specified in the header and not on the
        //  message's fields which may be version dependent
        let payload = &buf[..payload_len]; // payload length was sanitized before this function was called

        let result = if hash_for_payload(payload) != checksum {
            debug!("checksum mismatch in received message, skipping");
            None
        } else if BitcoinNetworkId::de_ser(magic) != Some(config.my_bitcoin_network) {
            // This check is deferred so the implementation can skip the payload and stay in sync - for
            //  what it's worth, this is a serious error
            warn!("message from different bitcoin network received (local {:08x}, remote {:08x}), skipping", config.my_bitcoin_network.ser(), magic);
            None
        } else {
            match command {
                Some(Command::Version) => do_parse_version(payload),
                Some(Command::VerAck) => do_parse_ver_ack(payload),
                _ => {
                    debug!("received unknown command, skipping");
                    None
                }
            }
        };
        buf.advance(payload_len);
        result
    }

    fn ser(&self, buf: &mut BytesMut, config: &BitcoinConfig) {
        buf.put_u32_le(config.my_bitcoin_network.ser());
        buf.put_slice(self.command_string());
        let payload = self.payload();
        buf.put_u32_le(payload.len().try_into().expect(
            "Correct code can never generate a payload with a size anywhere near u32 bounds",
        ));
        buf.put_u32_le(hash_for_payload(&payload));
        buf.put_slice(&payload);
    }
}

fn do_parse_version(payload: &[u8]) -> Option<BitcoinMessage> {
    let mut cursor = Cursor::new(payload);

    let version = BitcoinVersion(cursor.get_u32_le());
    let services = Services::from_bits_truncate(cursor.get_u64_le());
    let timestamp = Timestamp::de_ser(cursor.get_i64_le());
    let addr_recv = parse_network_address_without_timestamp(&mut cursor);

    Some(BitcoinMessage::Version {
        version,
        services,
        timestamp,
        addr_recv,
    })
}

fn parse_network_address_without_timestamp(
    data: &mut Cursor<&[u8]>,
) -> NetworkAddressWithoutTimestamp {
    let services = Services::from_bits_truncate(data.get_u64_le());

    let addr_raw = &data.chunk()[..16];
    let addr = if addr_raw.starts_with(b"\0\0\0\0\0\0\0\0\0\0\0\0") {
        let octets: [u8; 4] = (&addr_raw[12..]).try_into().unwrap();
        IpAddr::V4(Ipv4Addr::from(octets))
    } else {
        let octets: [u8; 16] = addr_raw.try_into().unwrap();
        IpAddr::V6(Ipv6Addr::from(octets))
    };
    data.advance(16);

    //NB: the port number is the only number that is encoded in network byte order
    let port = data.get_u16();

    NetworkAddressWithoutTimestamp {
        services,
        addr,
        port,
    }
}

fn do_parse_ver_ack(_payload: &[u8]) -> Option<BitcoinMessage> {
    Some(BitcoinMessage::VerAck)
}

fn hash_for_payload(payload: &[u8]) -> u32 {
    let first_round = Sha256::digest(payload);
    let second_round = Sha256::digest(&first_round);
    let mut buf: &[u8] = &second_round;
    buf.get_u32_le()
}

#[cfg(test)]
mod test {
    use std::ops::Deref;
    use std::str::FromStr;

    use bytes::BufMut;
    use rstest::*;
    use crate::generic::protocol::GenericP2PConfig;

    use super::*;

    #[test]
    fn test_ser_version_v4() {
        do_test_ser_version(
            IpAddr::V4(Ipv4Addr::from([51, 52, 53, 54])),
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 51, 52, 53, 54],
            &test_config(),
        );
    }

    #[test]
    fn test_ser_version_v6() {
        do_test_ser_version(
            IpAddr::V6(Ipv6Addr::from([
                100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
            ])),
            [
                100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
            ],
            &test_config(),
        );
    }

    fn do_test_ser_version(addr: IpAddr, addr_bytes: [u8; 16], config: &BitcoinConfig) {
        let msg = BitcoinMessage::Version {
            version: BitcoinVersion(60002),
            services: Services::NODE_XTHIN,
            timestamp: Timestamp::de_ser(1234567),
            addr_recv: NetworkAddressWithoutTimestamp {
                services: Services::NODE_XTHIN,
                addr,
                port: 0x888,
            },
        };
        let mut buf = BytesMut::new();
        msg.ser(&mut buf, config);

        let mut expected_payload = vec![
            0x62, 0xEA, 0, 0, // version
            16, 0, 0, 0, 0, 0, 0, 0, // services
            0x87, 0xD6, 0x12, 0, 0, 0, 0, 0, // timestamp
            16, 0, 0, 0, 0, 0, 0, 0, // addr_recv.services
        ];
        expected_payload.extend_from_slice(&addr_bytes);
        expected_payload.extend_from_slice(&[0x08, 0x88]); // port (NB: network byte order)
        for _ in 0..39 {
            expected_payload.push(0);
        }

        assert_eq!(
            buf.chunk(),
            message_data(None, COMMAND_VERSION, None, &expected_payload)
        );
    }

    #[test]
    fn test_ser_verack() {
        let mut buf = BytesMut::new();
        BitcoinMessage::VerAck.ser(&mut buf, &test_config());
        assert_eq!(
            buf.chunk(),
            message_data(None, COMMAND_VERACK, None, &vec![])
        );
    }

    #[rstest]
    #[case::empty              (vec![], false)]
    #[case::empty              (vec![0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0, 0,0,0,0], true)]
    #[case::incomplete_payload (vec![0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0, 1,0,0,0, 0,0,0,0], false)]
    #[case::complete_payload   (vec![0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0, 1,0,0,0, 0,0,0,0, 65], true)]
    #[case::not_too_long       (vec![0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0, 0x00,0x10,0,0, 0,0,0,0], false)]
    fn test_message_has_complete_message(#[case] buf: Vec<u8>, #[case] expected: bool) {
        assert_eq!(
            BitcoinMessage::has_complete_message(&buf, &test_config()).unwrap(),
            expected
        );
    }

    fn test_config() -> BitcoinConfig {
        BitcoinConfig {
            generic_config: GenericP2PConfig::new(SocketAddr::from_str("127.0.0.1:12345").unwrap()),
            my_version: BitcoinVersion(60002),
            my_bitcoin_network: BitcoinNetworkId::TestNetRegTest,
            my_services: Services::empty(),
            payload_size_limit: BitcoinConfig::DEFAULT_PAYLOAD_SIZE_LIMIT,
        }
    }

    #[test]
    fn test_message_has_complete_message_too_big() {
        let result = BitcoinMessage::has_complete_message(
            &vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0x10, 0, 0, 0, 0, 0, 0,
            ],
            &test_config(),
        );
        assert!(matches!(
            Err::<bool, BitcoinError>(BitcoinError::MessageTooBig),
            result
        ));
    }

    /// This is test data from the Bitcoin protocol documentation
    #[test]
    fn test_parse_version_message() {
        let payload = vec![
            0x62, 0xEA, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0x11, 0xB2, 0xD0, 0x50, 0, 0, 0, 0, 1, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0x3B, 0x2E,
            0xB3, 0x5D, 0x8C, 0xE6, 0x17, 0x65, 0x0F, 0x2F, 0x53, 0x61, 0x74, 0x6F, 0x73, 0x68,
            0x69, 0x3A, 0x30, 0x2E, 0x37, 0x2E, 0x32, 0x2F, 0xC0, 0x3E, 0x03, 0x00,
        ];

        assert_eq!(
            parse_message_data(None, b"version\0\0\0\0\0", None, &payload),
            Some(BitcoinMessage::Version {
                version: BitcoinVersion(0x0000EA62),
                services: Services::NODE_NETWORK,
                timestamp: Timestamp::de_ser(0x50D0B211),
                addr_recv: NetworkAddressWithoutTimestamp {
                    services: Services::NODE_NETWORK,
                    addr: IpAddr::V6(Ipv6Addr::from([
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0
                    ])),
                    port: 0,
                },
            })
        );
    }

    #[test]
    fn test_parse_verack_message() {
        assert_eq!(
            parse_message_data(None, COMMAND_VERACK, None, &vec![]),
            Some(BitcoinMessage::VerAck)
        );
    }

    fn message_data(
        magic: Option<u32>,
        command: &[u8],
        hash: Option<u32>,
        payload: &[u8],
    ) -> Vec<u8> {
        let magic = magic.unwrap_or(test_config().my_bitcoin_network.ser());
        let hash = hash.unwrap_or_else(|| hash_for_payload(payload));

        let mut buf = BytesMut::new();
        buf.put_u32_le(test_config().my_bitcoin_network.ser());
        buf.put_slice(command);
        buf.put_u32_le(payload.len() as u32);
        buf.put_u32_le(hash);
        buf.put_slice(payload);
        buf.to_vec()
    }

    fn parse_message_data(
        magic: Option<u32>,
        command: &[u8],
        hash: Option<u32>,
        payload: &[u8],
    ) -> Option<BitcoinMessage> {
        let vec = message_data(magic, command, hash, payload);
        let mut buf = BytesMut::from(vec.deref());
        buf.put_slice(&vec![55, 66]);
        let result = BitcoinMessage::parse_message(&mut buf, &test_config());
        assert_eq!(buf.chunk(), vec![55, 66].deref());
        result
    }

    #[test]
    fn test_parse_unknown_command() {
        assert_eq!(
            parse_message_data(None, b"other\0\0\0\0\0\0\0", None, &vec![]),
            None
        );
    }

    #[test]
    fn test_parse_wrong_hash() {
        assert_eq!(
            parse_message_data(None, COMMAND_VERACK, Some(123), &vec![]),
            None
        );
    }

    #[test]
    fn test_parse_magic_mismatch() {
        assert_eq!(
            parse_message_data(Some(123), COMMAND_VERACK, Some(123), &vec![]),
            None
        );
    }

    #[test]
    fn test_parse_network_address_without_version_ipv6() {
        let data = vec![
            4, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 4, 1, 99,
            88,
        ];
        let mut cursor = Cursor::new(data.deref());

        let parsed = parse_network_address_without_timestamp(&mut cursor);
        assert_eq!(
            parsed,
            NetworkAddressWithoutTimestamp {
                services: Services::NODE_BLOOM,
                addr: IpAddr::V6(Ipv6Addr::from([
                    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
                ])),
                port: 1025,
            }
        );

        assert_eq!(cursor.chunk(), &vec![99, 88]);
    }

    #[test]
    fn test_parse_network_address_without_version_ipv4() {
        let data = vec![
            4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 6, 7, 8, 4, 1, 99, 88,
        ];
        let slice: &[u8] = &data;
        let mut cursor = Cursor::new(slice);

        let parsed = parse_network_address_without_timestamp(&mut cursor);
        assert_eq!(
            parsed,
            NetworkAddressWithoutTimestamp {
                services: Services::NODE_BLOOM,
                addr: IpAddr::V4(Ipv4Addr::from([5, 6, 7, 8])),
                port: 1025,
            }
        );

        assert_eq!(cursor.chunk(), &vec![99, 88]);
    }

    #[test]
    fn test_do_parse_ver_ack() {
        assert_eq!(do_parse_ver_ack(b""), Some(BitcoinMessage::VerAck));
        assert_eq!(do_parse_ver_ack(b"abc"), Some(BitcoinMessage::VerAck));
    }

    #[rstest]
    #[case::empty(b"", 0xE2E0F65D)]
    // This is sample data comes from the Bitcoin protocol documentation
    #[case::version(&vec![
        0x62, 0xEA, 0, 0,
        1, 0, 0, 0, 0, 0, 0, 0,
        0x11, 0xB2, 0xD0, 0x50, 0, 0, 0, 0,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0,
        0x3B, 0x2E, 0xB3, 0x5D, 0x8C, 0xE6, 0x17, 0x65,
        0x0F, 0x2F, 0x53, 0x61, 0x74, 0x6F, 0x73, 0x68, 0x69, 0x3A, 0x30, 0x2E, 0x37, 0x2E, 0x32, 0x2F,
        0xC0, 0x3E, 0x03, 0x00],
    0x5A8D643B)]
    fn test_hash_for_payload(#[case] payload: &[u8], #[case] hash: u32) {
        assert_eq!(hash_for_payload(payload), hash);
    }
}

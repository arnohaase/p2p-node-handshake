use std::io::Cursor;
use std::mem::size_of;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bitflags::bitflags;
use bytes::{Buf, BytesMut};
use log::debug;
use sha2::{Digest, Sha256};

use crate::error::P2PError;

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

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Timestamp(u64);

/// Network address without timestamp - Bitcoin spec specifies a 'timestamp' as part of a network
///  address, everywhere except for Version messages
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NetworkAddressWithoutTimestamp {
    pub services: Services,
    pub addr: IpAddr,
    pub port: u16,
}

pub type Command = [u8;12];

const MESSAGE_HEADER_LEN_ON_NETWORK: usize = 4 + 12 + 4 + 4; // magic + command + length + checksum
const MESSAGE_HEADER_OFFS_PAYLOAD_LENGTH: usize = 4 + 12;    // magic + command

const PAYLOAD_SIZE_THRESHOLD: usize = 0x1000; //TODO make this configurable

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Message {
    Version {
        version: u32,
        services: Services,
        timestamp: Timestamp,
        addr_recv: NetworkAddressWithoutTimestamp,
    },
    VerAck,
}
impl Message {
    //TODO documentation
    pub fn has_complete_message(buf: &[u8]) -> Result<bool, P2PError> {
        if buf.len() < MESSAGE_HEADER_LEN_ON_NETWORK {
            return Ok(false);
        }
        let payload_len: usize = (&buf[MESSAGE_HEADER_OFFS_PAYLOAD_LENGTH..]).get_u32_le().try_into().expect("<32 bit system not supported");
        if payload_len > PAYLOAD_SIZE_THRESHOLD {
            return Err(P2PError::MessageTooBig);
        }
        Ok(buf.len() >= MESSAGE_HEADER_LEN_ON_NETWORK + payload_len)
    }

    /// todo documentation: assumes that the buffer contains an entire message, panicking otherwise
    /// todo  always consumes a message, returning None if the message was not recognized
    pub fn parse(buf: &mut BytesMut) -> Option<Message> {
        let magic = buf.get_u32_le();
        //TODO check magic number against (configured) own magic version

        //TODO avoid cloning - MessageKind enum?
        let command: Command = (&buf[..size_of::<Command>()]).try_into().unwrap();
        buf.advance(size_of::<Command>());

        let payload_len: usize = buf.get_u32_le().try_into().expect("<32 bit system not supported");
        let checksum = buf.get_u32_le();

        // implementation: decouple buffer advancement from payload handling - we want to advance
        //  the buffer's start based on the payload length specified in the header and not on the
        //  message's fields which may be version dependent
        let payload = &buf[..payload_len]; // payload length was sanitized before this function was called

        let result = if hash_for_payload(payload) != checksum {
            debug!("checksum mismatch in received message, skipping");
            None
        } else {
            match &command {
                b"version\0\0\0\0\0" => do_parse_version(payload),
                b"verack\0\0\0\0\0\0" => do_parse_ver_ack(payload),
                cmd => {
                    debug!("received unknown command {:?}, skipping", cmd);
                    None
                }
            }
        };
        buf.advance(payload_len);
        result
    }

}

fn do_parse_version(payload: &[u8]) -> Option<Message> {
    let mut cursor = Cursor::new(payload);

    let version = cursor.get_u32_le();
    let services = Services::from_bits_truncate(cursor.get_u64_le());
    let timestamp = Timestamp(cursor.get_u64_le());
    let addr_recv = parse_network_address_without_timestamp(&mut cursor);

    if services != addr_recv.services {
        //TODO context information in logging
        debug!("inconsistency in received version message: services != addr_recv.services - skipping");
        return None;
    }

    Some(Message::Version {
        version,
        services,
        timestamp,
        addr_recv,
    })
}

fn parse_network_address_without_timestamp(data: &mut Cursor<&[u8]>) -> NetworkAddressWithoutTimestamp {
    let services = Services::from_bits_truncate(data.get_u64_le());

    let addr_raw = &data.chunk()[..16];
    let addr = if addr_raw.starts_with(b"\0\0\0\0\0\0\0\0\0\0\0\0") {
        let octets: [u8;4] = (&addr_raw[12..]).try_into().unwrap();
        IpAddr::V4(Ipv4Addr::from(octets))
    } else {
        let octets: [u8;16] = addr_raw.try_into().unwrap();
        IpAddr::V6(Ipv6Addr::from(octets))
    };
    data.advance(16);

    //NB: the port number is the only number that is encoded in network byte order
    let port = data.get_u16();

    NetworkAddressWithoutTimestamp {
        services,
        addr,
        port
    }
}

fn do_parse_ver_ack(_payload: &[u8]) -> Option<Message> {
    Some(Message::VerAck)
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
    use bytes::BufMut;
    use rstest::*;

    use super::*;

    #[rstest]
    #[case::empty(vec![], Ok(false))]
    #[case::empty              (vec![0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0, 0,0,0,0], Ok(true))]
    #[case::incomplete_payload (vec![0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0, 1,0,0,0, 0,0,0,0], Ok(false))]
    #[case::complete_payload (vec![0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0, 1,0,0,0, 0,0,0,0, 65], Ok(true))]
    #[case::too_long           (vec![0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0, 0x01,0x10,0,0, 0,0,0,0], Err(P2PError::MessageTooBig))]
    #[case::not_too_long       (vec![0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0, 0x00,0x10,0,0, 0,0,0,0], Ok(false))]
    fn test_message_has_complete_message(#[case] buf: Vec<u8>, #[case] expected: Result<bool, P2PError>) {
        assert_eq!(Message::has_complete_message(&buf), expected);
    }

    #[test]
    fn test_parse_version_message() {
        let payload = vec![
            0x62, 0xEA, 0, 0,
            1, 0, 0, 0, 0, 0, 0, 0,
            0x11, 0xB2, 0xD0, 0x50, 0, 0, 0, 0,
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0,
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0, 0, 0,
            0x3B, 0x2E, 0xB3, 0x5D, 0x8C, 0xE6, 0x17, 0x65,
            0x0F, 0x2F, 0x53, 0x61, 0x74, 0x6F, 0x73, 0x68, 0x69, 0x3A, 0x30, 0x2E, 0x37, 0x2E, 0x32, 0x2F,
            0xC0, 0x3E, 0x03, 0x00];

        assert_eq!(parse_message_data(b"version\0\0\0\0\0", None, &payload), Some(Message::Version {
            version: 0x0000EA62,
            services: Services::NODE_NETWORK,
            timestamp: Timestamp(0x50D0B211),
            addr_recv: NetworkAddressWithoutTimestamp {
                services: Services::NODE_NETWORK,
                addr: IpAddr::V6(Ipv6Addr::from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0])),
                port: 0,
            },
        }));
    }

    #[test]
    fn test_parse_verack_message() {
        assert_eq!(parse_message_data(b"verack\0\0\0\0\0\0", None, &vec![]), Some(Message::VerAck));
    }

    fn parse_message_data(command: &[u8], hash: Option<u32>, payload: &[u8]) -> Option<Message> {
        let hash = hash.unwrap_or_else(|| hash_for_payload(payload));

        let mut buf = BytesMut::new();
        buf.put_u32_le(0);
        buf.put_slice(command);
        buf.put_u32_le(payload.len() as u32);
        buf.put_u32_le(hash);
        buf.put_slice(payload);
        buf.put_slice(&vec![55, 66]);
        let result = Message::parse(&mut buf);
        assert_eq!(buf.chunk(), vec![55, 66].deref());
        result
    }

    #[test]
    fn test_parse_unknown_command() {
        assert_eq!(parse_message_data(b"other\0\0\0\0\0\0\0", None, &vec![]), None);
    }

    #[test]
    fn test_parse_wrong_hash() {
        assert_eq!(parse_message_data(b"verack\0\0\0\0\0\0", Some(123), &vec![]), None);
    }

    #[test]
    fn test_parse_network_address_without_version_ipv6() { //TODO ipv4
        let data = vec![4,0,0,0,0,0,0,0, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 4,1, 99,88];
        let mut cursor = Cursor::new(data.deref());

        let parsed = parse_network_address_without_timestamp(&mut cursor);
        assert_eq!(parsed, NetworkAddressWithoutTimestamp {
            services: Services::NODE_BLOOM,
            addr: IpAddr::V6(Ipv6Addr::from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])),
            port: 1025,
        });

        assert_eq!(cursor.chunk(), &vec![99, 88]);
    }

    #[test]
    fn test_parse_network_address_without_version_ipv4() {
        let data = vec![4,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,5,6,7,8, 4,1, 99,88];
        let slice: &[u8] = &data;
        let mut cursor = Cursor::new(slice);

        let parsed = parse_network_address_without_timestamp(&mut cursor);
        assert_eq!(parsed, NetworkAddressWithoutTimestamp {
            services: Services::NODE_BLOOM,
            addr: IpAddr::V4(Ipv4Addr::from([5, 6, 7, 8])),
            port: 1025,
        });

        assert_eq!(cursor.chunk(), &vec![99, 88]);
    }

    #[test]
    fn test_do_parse_ver_ack() {
        assert_eq!(do_parse_ver_ack(b""), Some(Message::VerAck));
        assert_eq!(do_parse_ver_ack(b"abc"), Some(Message::VerAck));
    }

    #[rstest]
    #[case::empty(b"", 0xE2E0F65D)]
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
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Mutex;
use crate::connection::Connection;
use crate::error::P2PResult;
use crate::message::{Message, NetworkAddressWithoutTimestamp, Services, Timestamp};

pub struct NegotiatedVersion {
    pub peer_version: u32,
    pub peer_services: Services,
}

//TODO documentation - None means connection was closed
//TODO documentation - timeout via decorator
pub async fn handshake(connection: &mut Connection) -> P2PResult<Option<NegotiatedVersion>> {
    connection.send(&Message::Version {
        version: 0, //TODO config
        services: Services::empty(), //TODO config
        timestamp: Timestamp::now(),
        addr_recv: NetworkAddressWithoutTimestamp {
            services: Services::empty(), //TODO config
            addr: IpAddr::V4(Ipv4Addr::from([127, 0, 0, 1])), //TODO
            port: 12345, //TODO
        },
    }).await?;

    let verack_received = AtomicBool::new(false);
    let mut peer_info = Mutex::new(None);

    loop {
        match connection.receive().await? {
            None => return Ok(None),
            Some(Message::Version {
                     version,
                     services,
                     timestamp,
                     addr_recv
                 }) => {
                let mut lock = peer_info.lock().await;
                *lock = Some((version, services));
            },
            Some(Message::VerAck) => verack_received.store(true, Ordering::Release),
        }

        if verack_received.load(Ordering::Acquire) {
            let lock = peer_info.lock().await;
            if let Some((version, services)) = lock.as_ref() {
                return Ok(Some(NegotiatedVersion {
                    peer_version: *version,
                    peer_services: *services,
                }));
            }
        }
    }
}
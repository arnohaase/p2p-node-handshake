use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::Mutex;
use crate::connection::Connection;
use crate::error::P2PResult;
use crate::message::{Message, NetworkAddressWithoutTimestamp, Services, Timestamp, Version};

pub struct NegotiatedVersion { //TODO better name?
    pub peer_version: Version,
    pub peer_services: Services,
}

//TODO documentation - None means connection was closed
//TODO documentation - timeout via decorator
pub async fn handshake(connection: &mut Connection) -> P2PResult<Option<NegotiatedVersion>> {
    connection.send(&Message::Version {
        version: connection.config.my_version,
        services: connection.config.my_services,
        timestamp: Timestamp::now(),
        addr_recv: NetworkAddressWithoutTimestamp::new(&connection.peer_address, connection.config.as_ref()),
    }).await?;

    let verack_received = AtomicBool::new(false);
    let peer_info = Mutex::new(None);

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
                connection.send(&Message::VerAck).await?;
            },
            Some(Message::VerAck) => verack_received.store(true, Ordering::Release),

            // TODO ignore other messages as they are added
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
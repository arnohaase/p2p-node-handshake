use std::net::SocketAddr;
use crate::message::{Services, Version};

pub struct Config {
    pub my_address: SocketAddr,
    pub my_version: Version,
    pub my_services: Services,
    pub payload_size_limit: usize,
}
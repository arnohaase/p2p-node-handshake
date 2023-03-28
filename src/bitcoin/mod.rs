/// Bitcoin specific configuration data structures
pub mod config;
/// Bitcoin specific error type
pub mod error;
/// Bitcoin specific message implementation, including serializing and deserializing the wire format
pub mod message;
/// The Bitcoin 'protocol', i.e. mapping the generic algorithms to Bitcoin's specifics
pub mod protocol;
/// Small Bitcoin specific types, like timestamp or version
pub mod types;

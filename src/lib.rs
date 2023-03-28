#![warn(missing_docs, rust_2018_idioms)]

pub mod connection;
pub mod error;
pub mod handshake;
pub mod message;
pub mod server;


#[cfg(test)]
#[ctor::ctor]
/// enable logging in test code
fn init_logging() {
    simple_logger::SimpleLogger::new()
        .with_colors(true)
        .with_level(log::LevelFilter::Debug)
        .init()
        .unwrap();
}

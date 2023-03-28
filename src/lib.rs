//! This is my solution for Eiger's coding challenge - see README.md for details.
//!
//! It is an implementation of Bitcoin's p2p handshake. The code is organized in the [generic]
//!  module with protocol independent connection and handshake handling, and [bitcoin] with the
//!  bitcoin specific messages and handshake details.

#![warn(missing_docs, rust_2018_idioms)]

/// Bitcoin specific messages and handshake protocol
pub mod bitcoin;
/// Bitcoin independent connection handling and four-way handshake
pub mod generic;

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

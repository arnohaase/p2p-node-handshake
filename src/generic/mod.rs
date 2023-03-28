
/// Protocol independent connection implementation
pub mod connection;
/// Protocol independent implementation of a four-way handshake
pub mod four_way_handshake;
/// SPI to allow protocol specific code to use the generic connection and handshake implementation
pub mod protocol;
/// Protocol independent implementation of a listening socket, allowing peers to connect and
///  spawning connections when they do
pub mod server;
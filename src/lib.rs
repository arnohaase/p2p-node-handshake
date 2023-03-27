#![warn(missing_docs, rust_2018_idioms)]

pub mod error;
pub mod message;

#[cfg(test)]
#[ctor::ctor]
fn init_logging() {
    simple_logger::SimpleLogger::new()
        .with_colors(true)
        .with_level(log::LevelFilter::Debug)
        .init()
        .unwrap();
}

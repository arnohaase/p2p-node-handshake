#![warn(missing_docs, rust_2018_idioms)]

pub mod bitcoin;
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

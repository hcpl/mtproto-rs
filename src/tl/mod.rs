//! Definitions to represent Type Language concepts in Rust.

pub mod dynamic;
pub mod gzip_packed;
pub mod message;
pub mod rpc_result;

pub use self::dynamic::{TLConstructorsMap, TLObject};

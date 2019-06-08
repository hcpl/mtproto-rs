// `error_chain!` can nest quite deeply
#![recursion_limit = "172"]

#![cfg_attr(feature = "async-await-preview", feature(async_await))]


#[cfg(not(any(feature = "non-openssl-impls", feature = "openssl")))]
compile_error!("\
    At least one of the features \"non-openssl-impls\" or \"openssl\" \
    must be enabled for this crate.\
");



#[macro_use]
mod utils;

pub(crate) mod async_io;
pub(crate) mod bigint;
pub(crate) mod crypto;

#[cfg(feature = "async-await-preview")]
pub mod async_await;
pub mod error;
pub mod manual_types;
pub mod network;
pub mod protocol;
pub mod server;
pub mod tl;

// Use this hack because `include!` and top-level inner attributes don't mix well
include!(concat!(env!("OUT_DIR"), "/schema.rs"));


pub use crate::error::{Error, ErrorKind, Result, ResultExt};
pub use crate::tl::TLObject;

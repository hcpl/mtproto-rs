// `error_chain!` can nest quite deeply
#![recursion_limit = "168"]

#[macro_use]
extern crate arrayref;
extern crate byteorder;
#[macro_use]
extern crate cfg_if;
extern crate chrono;
extern crate crc;
extern crate envy;
extern crate erased_serde;
#[macro_use]
extern crate error_chain;
extern crate flate2;
extern crate futures;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate num_traits;
extern crate rand;
extern crate select;
extern crate serde;
extern crate serde_bytes;
#[macro_use]
extern crate serde_derive;
extern crate serde_mtproto;
#[macro_use]
extern crate serde_mtproto_derive;
extern crate tokio_io;
extern crate tokio_tcp;
extern crate toml;

cfg_if! {
    if #[cfg(feature = "non-openssl-impls")] {
        extern crate aes;
        extern crate base64;
        extern crate der_parser;
        extern crate digest;
        extern crate nom;
        extern crate num_bigint;
        extern crate sha1;
        extern crate sha2;
    }
}

cfg_if! {
    if #[cfg(feature = "openssl")] {
        extern crate openssl;
    }
}

cfg_if! {
    if #[cfg(not(any(feature = "non-openssl-impls", feature = "openssl")))] {
        compile_error!("\
            At least one of the features \"non-openssl-impls\" or \"openssl\" \
            must be enabled for this crate.\
        ");
    }
}


mod manual_types;
#[macro_use]
mod utils;

pub(crate) mod bigint;
pub(crate) mod crypto;

pub mod error;
pub mod network;
pub mod protocol;
pub mod rpc;
pub mod tl;

// Use this hack because `include!` and top-level inner attributes don't mix well
include!(concat!(env!("OUT_DIR"), "/schema.rs"));


pub use error::{Error, ErrorKind, Result, ResultExt};
pub use tl::TLObject;

// `error_chain!` can nest quite deeply
#![recursion_limit = "160"]

extern crate byteorder;
extern crate chrono;
extern crate crc;
extern crate envy;
extern crate erased_serde;
#[macro_use]
extern crate error_chain;
extern crate extprim;
extern crate futures;
extern crate hyper;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate num_traits;
extern crate openssl;
extern crate rand;
extern crate select;
extern crate serde;
extern crate serde_bytes;
#[macro_use]
extern crate serde_derive;
extern crate serde_mtproto;
#[macro_use]
extern crate serde_mtproto_derive;
extern crate tokio_core;
extern crate tokio_io;
extern crate toml;


mod manual_types;
mod utils;

pub mod error;
pub mod rpc;
pub mod schema;
pub mod tl;


pub use error::{Error, ErrorKind, Result, ResultExt};
pub use rpc::{AppInfo, Session};
pub use tl::TLObject;

use std::fmt;
use std::net::SocketAddr;

use futures::Future;
use serde::ser::Serialize;
use serde::de::DeserializeOwned;

use ::error;
use ::tl::TLObject;
use ::network::state::State;


lazy_static! {
    pub static ref SERVER_ADDRS: [SocketAddr; 1] = [
        ([149, 154, 167, 51], 443).into(),
    ];
}


pub trait Connection: Send + Sized + 'static {
    fn request_plain<T, U>(self, state: State, request_data: T)
        -> Box<Future<Item = (Self, State, U), Error = error::Error> + Send>
        where T: fmt::Debug + Serialize + TLObject + Send,
              U: fmt::Debug + DeserializeOwned + TLObject + Send;

    fn request<T, U>(self, state: State, request_data: T)
        -> Box<Future<Item = (Self, State, U), Error = error::Error> + Send>
        where T: fmt::Debug + Serialize + TLObject + Send,
              U: fmt::Debug + DeserializeOwned + TLObject + Send;
}

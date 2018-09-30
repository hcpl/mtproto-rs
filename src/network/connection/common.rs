use std::fmt;
use std::net::SocketAddr;

use futures::Future;
use serde::ser::Serialize;
use serde::de::DeserializeOwned;
use tokio_io::{self, AsyncWrite};

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
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        U: fmt::Debug + DeserializeOwned + TLObject + Send;

    fn request<T, U>(self, state: State, request_data: T)
        -> Box<Future<Item = (Self, State, U), Error = error::Error> + Send>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        U: fmt::Debug + DeserializeOwned + TLObject + Send;
}


pub(super) fn perform_send<S>(send: S, message_bytes: Vec<u8>)
    -> impl Future<Item = S, Error = error::Error>
where
    S: fmt::Debug + AsyncWrite,
{
    tokio_io::io::write_all(send, message_bytes).map(|(send, sent_bytes)| {
        debug!("Sent {} bytes to server: send = {:?}, bytes = {:?}",
            sent_bytes.len(), send, sent_bytes);

        send
    }).map_err(Into::into)
}

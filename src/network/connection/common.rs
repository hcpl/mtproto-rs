use std::fmt;
use std::net::SocketAddr;

use futures::Future;
use serde::ser::Serialize;
use serde::de::DeserializeOwned;
use serde_mtproto::MtProtoSized;
use tokio_io::{self, AsyncWrite};

use ::error::{self, ErrorKind};
use ::tl::TLObject;
use ::tl::message::MessageCommon;
use ::network::state::State;


lazy_static! {
    pub static ref SERVER_ADDRS: [SocketAddr; 1] = [
        ([149, 154, 167, 51], 443).into(),
    ];
}


pub trait Connection: Send + Sized + 'static {
    type SendConnection: SendConnection;
    type RecvConnection: RecvConnection;

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

    fn split(self) -> (Self::SendConnection, Self::RecvConnection);
}

pub trait SendConnection: Send + Sized + 'static {
    fn send_plain<T>(self, state: State, send_data: T)
        -> Box<Future<Item = (Self, State), Error = error::Error> + Send>
    where
        T: fmt::Debug + Serialize + TLObject + Send;

    fn send<T>(self, state: State, send_data: T)
        -> Box<Future<Item = (Self, State), Error = error::Error> + Send>
    where
        T: fmt::Debug + Serialize + TLObject + Send;
}

pub trait RecvConnection: Send + Sized + 'static {
    fn recv_plain<U>(self, state: State)
        -> Box<Future<Item = (Self, State, U), Error = error::Error> + Send>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send;

    fn recv<U>(self, state: State)
        -> Box<Future<Item = (Self, State, U), Error = error::Error> + Send>
    where
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

pub(super) fn from_raw<U, N>(raw_message: &N::Raw, state: &State) -> error::Result<N>
where
    U: fmt::Debug + DeserializeOwned + TLObject + Send,
    N: MessageCommon<U>,
{
    if let Some(variant_names) = U::all_enum_variant_names() {
        // FIXME: Lossy error management
        for vname in variant_names {
            if let Ok(msg) = N::from_raw(raw_message, state.auth_raw_key(), state.version, &[vname]) {
                return Ok(msg);
            }
        }

        bail!(ErrorKind::BadTcpMessage(raw_message.size_hint()?))
    } else {
        N::from_raw(raw_message, state.auth_raw_key(), state.version, &[])
    }
}

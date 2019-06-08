use std::fmt;
use std::marker::Unpin;
use std::net::SocketAddr;

use error_chain::bail;
use futures_io::AsyncWrite;
use futures_util::AsyncWriteExt;
use log::debug;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_mtproto::MtProtoSized;

use crate::error::{self, ErrorKind};
use crate::tl::TLObject;
use crate::tl::message::{MessageCommon, RawMessageCommon};
use crate::network::state::State;


#[async_transform::trait_decl_async_methods_to_box_futures]
pub trait Connection: Send + Sized {
    type SendConnection: SendConnection;
    type RecvConnection: RecvConnection;

    async fn connect(server_addr: SocketAddr) -> error::Result<Self>;
    async fn with_default_server() -> error::Result<Self>;

    async fn request_plain<T, U>(&mut self, state: &mut State, request_data: T) -> error::Result<U>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        U: fmt::Debug + DeserializeOwned + TLObject + Send;

    async fn request<T, U>(&mut self, state: &mut State, request_data: T) -> error::Result<U>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        U: fmt::Debug + DeserializeOwned + TLObject + Send;

    fn split(self) -> (Self::SendConnection, Self::RecvConnection);
}

#[async_transform::trait_decl_async_methods_to_box_futures]
pub trait SendConnection: Send + Sized {
    async fn send_plain<T>(&mut self, state: &mut State, send_data: T) -> error::Result<()>
    where
        T: fmt::Debug + Serialize + TLObject + Send;

    async fn send<T>(&mut self, state: &mut State, send_data: T) -> error::Result<()>
    where
        T: fmt::Debug + Serialize + TLObject + Send;

    async fn send_raw<R>(&mut self, raw_message: &R) -> error::Result<()>
    where
        R: RawMessageCommon + Sync;
}

#[async_transform::trait_decl_async_methods_to_box_futures]
pub trait RecvConnection: Send + Sized {
    async fn recv_plain<U>(&mut self, state: &mut State) -> error::Result<U>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send;

    async fn recv<U>(&mut self, state: &mut State) -> error::Result<U>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send;

    async fn recv_raw<S>(&mut self) -> error::Result<S>
    where
        S: RawMessageCommon;
}

#[async_transform::async_fn_to_impl_future]
pub(super) async fn perform_send<S>(send: &mut S, message_bytes: &[u8]) -> error::Result<()>
where
    S: fmt::Debug + AsyncWrite + Unpin,
{
    send.write_all(message_bytes).await?;

    debug!("Sent {} bytes to server: send = {:?}, bytes = {:?}",
        message_bytes.len(), send, message_bytes);

    Ok(())
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

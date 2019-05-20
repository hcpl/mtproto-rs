use std::fmt;
use std::marker::Unpin;
use std::mem;
use std::net::SocketAddr;

use byteorder::{ByteOrder, LittleEndian};
use error_chain::bail;
use futures_io::AsyncRead;
use futures_util::compat::{AsyncRead01CompatExt, Future01CompatExt};
use futures_util::io::AsyncReadExt;
use log::{debug, info};
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use tokio_tcp::TcpStream;

use crate::error::{self, ErrorKind};
use crate::async_await::network::connection::common::{
    self, DEFAULT_SERVER_ADDR, Connection, RecvConnection, SendConnection,
};
use crate::async_await::network::connection::tcp_common;
use crate::network::state::State;
use crate::tl::TLObject;
use crate::tl::message::{Message, MessageCommon, MessagePlain, RawMessageCommon};


#[derive(Debug)]
pub struct ConnectionTcpAbridged {
    socket: TcpStream,
    is_first_request: bool,
}

#[async_transform::impl_async_methods_to_impl_futures]
impl ConnectionTcpAbridged {
    pub async fn connect(server_addr: SocketAddr) -> error::Result<Self> {
        info!("New TCP connection in abridged mode to {}", server_addr);
        let socket = TcpStream::connect(&server_addr).compat().await?;

        Ok(Self { socket, is_first_request: true })
    }

    pub async fn with_default_server() -> error::Result<Self> {
        Self::connect(*DEFAULT_SERVER_ADDR).await
    }


    pub async fn send_plain<T>(&mut self, state: &mut State, send_data: T) -> error::Result<()>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
    {
        self.impl_send::<T, MessagePlain<T>>(state, send_data).await
    }

    pub async fn send<T>(&mut self, state: &mut State, send_data: T) -> error::Result<()>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
    {
        self.impl_send::<T, Message<T>>(state, send_data).await
    }

    async fn impl_send<T, M>(&mut self, state: &mut State, send_data: T) -> error::Result<()>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        M: MessageCommon<T>,
    {
        let request_message = state.create_message::<T, M>(send_data)?;
        debug!("Message to send: {:?}", request_message);

        let raw_message = request_message.to_raw(state.auth_raw_key(), state.version)?;
        self.send_raw(&raw_message).await
    }

    pub async fn send_raw<R>(&mut self, raw_message: &R) -> error::Result<()>
    where
        R: RawMessageCommon,
    {
        debug!("Raw message to send: {:?}", raw_message);
        let data = prepare_send_data(raw_message, &mut self.is_first_request)?;

        let socket_mut = &mut self.socket;
        let mut socket_mut03 = socket_mut.compat();
        common::perform_send(&mut socket_mut03, &data).await
    }


    pub async fn recv_plain<U, N>(&mut self, state: &mut State) -> error::Result<U>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_recv::<U, MessagePlain<U>>(state).await
    }

    pub async fn recv<U, N>(&mut self, state: &mut State) -> error::Result<U>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_recv::<U, Message<U>>(state).await
    }

    async fn impl_recv<U, N>(&mut self, state: &mut State) -> error::Result<U>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
        N: MessageCommon<U>,
    {
        let raw_message = self.recv_raw().await?;
        let message = common::from_raw::<U, N>(&raw_message, state)?;
        debug!("Received message: {:?}", message);

        Ok(message.into_body())
    }

    pub async fn recv_raw<S>(&mut self) -> error::Result<S>
    where
        S: RawMessageCommon,
    {
        let socket_mut = &mut self.socket;
        let mut socket_mut03 = socket_mut.compat();
        let data = perform_recv(&mut socket_mut03).await?;
        let raw_message = tcp_common::parse_response::<S>(&data)?;
        debug!("Received raw message: {:?}", raw_message);

        Ok(raw_message)
    }


    pub async fn request_plain<T, U>(&mut self, state: &mut State, request_data: T) -> error::Result<U>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_request::<T, U, MessagePlain<T>, MessagePlain<U>>(state, request_data).await
    }

    pub async fn request<T, U>(&mut self, state: &mut State, request_data: T) -> error::Result<U>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_request::<T, U, Message<T>, Message<U>>(state, request_data).await
    }

    async fn impl_request<T, U, M, N>(&mut self, state: &mut State, request_data: T) -> error::Result<U>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
        M: MessageCommon<T>,
        N: MessageCommon<U>,
    {
        self.impl_send::<T, M>(state, request_data).await?;
        self.impl_recv::<U, N>(state).await
    }
}


#[async_transform::trait_impl_async_methods_to_box_futures]
impl Connection for ConnectionTcpAbridged {
    type SendConnection = SendConnectionTcpAbridged;
    type RecvConnection = RecvConnectionTcpAbridged;

    async fn connect(server_addr: SocketAddr) -> error::Result<Self> {
        Self::connect(server_addr).await
    }

    async fn with_default_server() -> error::Result<Self> {
        Self::with_default_server().await
    }

    async fn request_plain<T, U>(&mut self, state: &mut State, request_data: T) -> error::Result<U>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.request_plain(state, request_data).await
    }

    async fn request<T, U>(&mut self, state: &mut State, request_data: T) -> error::Result<U>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.request(state, request_data).await
    }

    fn split(self) -> (Self::SendConnection, Self::RecvConnection) {
        self.split()
    }
}


#[derive(Debug)]
pub struct SendConnectionTcpAbridged {
    send_socket: futures_util::io::WriteHalf<futures_util::compat::Compat01As03<TcpStream>>,
    is_first_request: bool,
}

#[derive(Debug)]
pub struct RecvConnectionTcpAbridged {
    recv_socket: futures_util::io::ReadHalf<futures_util::compat::Compat01As03<TcpStream>>,
}

impl ConnectionTcpAbridged {
    pub fn split(self) -> (SendConnectionTcpAbridged, RecvConnectionTcpAbridged) {
        let Self { socket, is_first_request } = self;
        let (recv_socket, send_socket) = socket.compat().split();

        (
            SendConnectionTcpAbridged { send_socket, is_first_request },
            RecvConnectionTcpAbridged { recv_socket },
        )
    }
}

#[async_transform::impl_async_methods_to_impl_futures]
impl SendConnectionTcpAbridged {
    pub async fn send_plain<T>(&mut self, state: &mut State, send_data: T) -> error::Result<()>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
    {
        self.impl_send::<T, MessagePlain<T>>(state, send_data).await
    }

    pub async fn send<T>(&mut self, state: &mut State, send_data: T) -> error::Result<()>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
    {
        self.impl_send::<T, Message<T>>(state, send_data).await
    }

    async fn impl_send<T, M>(&mut self, state: &mut State, send_data: T) -> error::Result<()>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        M: MessageCommon<T>,
    {
        let request_message = state.create_message::<T, M>(send_data)?;
        debug!("Message to send: {:?}", request_message);

        let raw_message = request_message.to_raw(state.auth_raw_key(), state.version)?;
        self.send_raw(&raw_message).await
    }

    async fn send_raw<R>(&mut self, raw_message: &R) -> error::Result<()>
    where
        R: RawMessageCommon,
    {
        debug!("Raw message to send: {:?}", raw_message);
        let data = prepare_send_data(raw_message, &mut self.is_first_request)?;

        common::perform_send(&mut self.send_socket, &data).await
    }
}

#[async_transform::impl_async_methods_to_impl_futures]
impl RecvConnectionTcpAbridged {
    pub async fn recv_plain<U>(&mut self, state: &mut State) -> error::Result<U>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_recv::<U, MessagePlain<U>>(state).await
    }

    pub async fn recv<U>(&mut self, state: &mut State) -> error::Result<U>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_recv::<U, Message<U>>(state).await
    }

    async fn impl_recv<U, N>(&mut self, state: &mut State) -> error::Result<U>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
        N: MessageCommon<U>,
    {
        let raw_message = self.recv_raw().await?;
        let message = common::from_raw::<U, N>(&raw_message, state)?;
        debug!("Received message: {:?}", message);

        Ok(message.into_body())
    }

    pub async fn recv_raw<S>(&mut self) -> error::Result<S>
    where
        S: RawMessageCommon,
    {
        let data = perform_recv(&mut self.recv_socket).await?;
        let raw_message = tcp_common::parse_response::<S>(&data)?;
        debug!("Received raw message: {:?}", raw_message);

        Ok(raw_message)
    }
}

#[async_transform::trait_impl_async_methods_to_box_futures]
impl SendConnection for SendConnectionTcpAbridged {
    async fn send_plain<T>(&mut self, state: &mut State, send_data: T) -> error::Result<()>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
    {
        self.send_plain(state, send_data).await
    }

    async fn send<T>(&mut self, state: &mut State, send_data: T) -> error::Result<()>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
    {
        self.send(state, send_data).await
    }

    async fn send_raw<R>(&mut self, raw_message: &R) -> error::Result<()>
    where
        R: RawMessageCommon + Sync,
    {
        self.send_raw(raw_message).await
    }
}

#[async_transform::trait_impl_async_methods_to_box_futures]
impl RecvConnection for RecvConnectionTcpAbridged {
    async fn recv_plain<U>(&mut self, state: &mut State) -> error::Result<U>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.recv_plain(state).await
    }

    async fn recv<U>(&mut self, state: &mut State) -> error::Result<U>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.recv(state).await
    }

    async fn recv_raw<S>(&mut self) -> error::Result<S>
    where
        S: RawMessageCommon,
    {
        self.recv_raw().await
    }
}


async fn perform_recv<R>(recv: &mut R) -> error::Result<Vec<u8>>
where
    R: fmt::Debug + AsyncRead + Unpin,
{
    let mut byte_id = [0; 1];
    recv.read_exact(&mut byte_id).await?;

    debug!("Received {} bytes from server: recv = {:?}, bytes = {:?}",
        byte_id.len(), recv, byte_id);

    let len = if byte_id == [0x7f] {
        let mut bytes_len = [0; 3];
        recv.read_exact(&mut bytes_len).await?;

        debug!("Received {} bytes from server: recv = {:?}, bytes = {:?}",
            bytes_len.len(), recv, bytes_len);

        LittleEndian::read_uint(&bytes_len, 3) as usize * 4
    } else {
        byte_id[0] as usize * 4
    };

    debug!("Got length from server: recv = {:?}, length = {}", recv, len);

    let mut body = vec![0; len];
    recv.read_exact(&mut body).await?;

    Ok(body)
}

fn prepare_send_data<R>(raw_message: &R, is_first_request: &mut bool) -> error::Result<Vec<u8>>
where
    R: RawMessageCommon,
{
    let size_div_4 = raw_message.size_hint()? / 4;  // div 4 required for abridged mode
    if size_div_4 > 0xff_ff_ff {
        bail!(ErrorKind::MessageTooLong(size_div_4 * 4));
    }

    // For overall efficiency we trade code conciseness for reduced amount of dynamic
    // allocations since computation redundancy here will likely cost less than overhead of
    // consecutive allocations.
    let first_request_offset = if *is_first_request { 1 } else { 0 };
    let msg_offset = first_request_offset + if size_div_4 < 0x7f { 1 } else { 4 };

    let mut buf = vec![0; msg_offset + size_div_4 * 4];

    if mem::replace(is_first_request, false) {
        buf[0] = 0xef;
    }

    if size_div_4 < 0x7f {
        buf[first_request_offset] = size_div_4 as u8;
    } else {
        let x = first_request_offset;
        buf[x] = 0x7f;
        // safe to cast here, x <= 0xff_ff_ff < u64::MAX
        LittleEndian::write_uint(&mut buf[x+1..x+4], size_div_4 as u64, 3);
    }

    serde_mtproto::to_writer(&mut buf[msg_offset..], raw_message)?;

    Ok(buf)
}

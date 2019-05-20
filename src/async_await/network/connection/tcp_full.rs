use std::fmt;
use std::marker::Unpin;
use std::mem;
use std::net::SocketAddr;

use byteorder::{ByteOrder, LittleEndian};
use crc::crc32;
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
use crate::utils::safe_uint_cast;


#[derive(Debug)]
pub struct ConnectionTcpFull {
    socket: TcpStream,
    sent_counter: u32,
}

#[async_transform::impl_async_methods_to_impl_futures]
impl ConnectionTcpFull {
    pub async fn connect(server_addr: SocketAddr) -> error::Result<Self> {
        info!("New TCP connection in full mode to {}", server_addr);
        let socket = TcpStream::connect(&server_addr).compat().await?;

        Ok(Self { socket, sent_counter: 0 })
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
        let data = prepare_send_data(raw_message, &mut self.sent_counter)?;

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
impl Connection for ConnectionTcpFull {
    type SendConnection = SendConnectionTcpFull;
    type RecvConnection = RecvConnectionTcpFull;

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
pub struct SendConnectionTcpFull {
    send_socket: futures_util::io::WriteHalf<futures_util::compat::Compat01As03<TcpStream>>,
    sent_counter: u32,
}

#[derive(Debug)]
pub struct RecvConnectionTcpFull {
    recv_socket: futures_util::io::ReadHalf<futures_util::compat::Compat01As03<TcpStream>>,
}

impl ConnectionTcpFull {
    pub fn split(self) -> (SendConnectionTcpFull, RecvConnectionTcpFull) {
        let Self { socket, sent_counter } = self;
        let (recv_socket, send_socket) = socket.compat().split();

        (
            SendConnectionTcpFull { send_socket, sent_counter },
            RecvConnectionTcpFull { recv_socket },
        )
    }
}

#[async_transform::impl_async_methods_to_impl_futures]
impl SendConnectionTcpFull {
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
        let data = prepare_send_data(raw_message, &mut self.sent_counter)?;

        common::perform_send(&mut self.send_socket, &data).await
    }
}

#[async_transform::impl_async_methods_to_impl_futures]
impl RecvConnectionTcpFull {
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
impl SendConnection for SendConnectionTcpFull {
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
impl RecvConnection for RecvConnectionTcpFull {
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
    let mut first_bytes = [0; 8];
    recv.read_exact(&mut first_bytes).await?;

    debug!("Received {} bytes from server: recv = {:?}, bytes = {:?}",
        first_bytes.len(), recv, first_bytes);

    let len = LittleEndian::read_u32(&first_bytes[0..4]);
    let ulen = len as usize;  // FIXME: use safe cast here
    // TODO: check seq_no
    let _seq_no = LittleEndian::read_u32(&first_bytes[4..8]);

    let mut last_bytes = vec![0; ulen - 8];
    recv.read_exact(&mut last_bytes).await?;

    debug!("Received {} bytes from server: recv = {:?}, bytes = {:?}",
        last_bytes.len(), recv, last_bytes);

    let checksum = LittleEndian::read_u32(&last_bytes[ulen - 12..ulen - 8]);
    let mut body = last_bytes;
    body.truncate(ulen - 12);

    let mut value = 0;
    value = crc32::update(value, &crc32::IEEE_TABLE, &first_bytes[0..4]);
    value = crc32::update(value, &crc32::IEEE_TABLE, &first_bytes[4..8]);
    value = crc32::update(value, &crc32::IEEE_TABLE, &body);

    if value == checksum {
        Ok(body)
    } else {
        bail!(ErrorKind::TcpFullModeResponseInvalidChecksum(value, checksum));
    }
}

fn prepare_send_data<R>(raw_message: &R, sent_counter: &mut u32) -> error::Result<Vec<u8>>
where
    R: RawMessageCommon,
{
    const SIZE_SIZE: usize = mem::size_of::<u32>();
    const SENT_COUNTER_SIZE: usize = mem::size_of::<u32>();
    let raw_message_size = raw_message.size_hint()?;
    const CRC_SIZE: usize = mem::size_of::<u32>();

    // FIXME: May overflow on 32-bit systems
    let data_size = SIZE_SIZE + SENT_COUNTER_SIZE + raw_message_size + CRC_SIZE;

    if let Ok(data_size_u32) = safe_uint_cast::<usize, u32>(data_size) {
        let mut buf = vec![0; data_size];

        {
            let (size_bytes, rest) = buf.split_at_mut(SIZE_SIZE);
            let (sent_counter_bytes, rest2) = rest.split_at_mut(SENT_COUNTER_SIZE);
            let (message_bytes, _) = rest2.split_at_mut(raw_message_size);

            LittleEndian::write_u32(size_bytes, data_size_u32);
            LittleEndian::write_u32(sent_counter_bytes, *sent_counter);
            serde_mtproto::to_writer(message_bytes, raw_message)?;
        }

        {
            let (non_crc_bytes, crc_bytes) = buf.split_at_mut(data_size - CRC_SIZE);

            let crc = crc32::checksum_ieee(&*non_crc_bytes);
            LittleEndian::write_u32(crc_bytes, crc);
        }

        *sent_counter += 1;

        Ok(buf)
    } else {
        bail!(ErrorKind::MessageTooLong(data_size));
    }
}

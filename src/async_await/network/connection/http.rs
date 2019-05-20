use std::fmt;
use std::marker::Unpin;
use std::net::SocketAddr;
use std::str;

use error_chain::bail;
use futures_io::AsyncRead;
use futures_util::compat::{AsyncRead01CompatExt, Future01CompatExt};
use futures_util::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use futures_util::stream::StreamExt;
use log::{debug, error, info};
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use tokio_tcp::TcpStream;

use crate::error::{self, ErrorKind};
use crate::async_await::network::connection::common::{
    self, DEFAULT_SERVER_ADDR, Connection, RecvConnection, SendConnection,
};
use crate::network::state::State;
use crate::tl::TLObject;
use crate::tl::message::{Message, MessageCommon, MessagePlain, RawMessageCommon, RawMessageSeedCommon};


#[derive(Debug)]
pub struct ConnectionHttp {
    socket: TcpStream,
}

#[async_transform::impl_async_methods_to_impl_futures]
impl ConnectionHttp {
    pub async fn connect(server_addr: SocketAddr) -> error::Result<Self> {
        info!("New HTTP connection to {}", server_addr);
        let socket = TcpStream::connect(&server_addr).compat().await?;

        Ok(Self { socket })
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
        let data = prepare_send_data(raw_message)?;

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
        let raw_message = parse_response::<S>(&data)?;
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
impl Connection for ConnectionHttp {
    type SendConnection = SendConnectionHttp;
    type RecvConnection = RecvConnectionHttp;

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
pub struct SendConnectionHttp {
    send_socket: futures_util::io::WriteHalf<futures_util::compat::Compat01As03<TcpStream>>,
}

#[derive(Debug)]
pub struct RecvConnectionHttp {
    recv_socket: futures_util::io::ReadHalf<futures_util::compat::Compat01As03<TcpStream>>,
}

impl ConnectionHttp {
    pub fn split(self) -> (SendConnectionHttp, RecvConnectionHttp) {
        let (recv_socket, send_socket) = self.socket.compat().split();

        (
            SendConnectionHttp { send_socket },
            RecvConnectionHttp { recv_socket },
        )
    }
}

#[async_transform::impl_async_methods_to_impl_futures]
impl SendConnectionHttp {
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
        let data = prepare_send_data(raw_message)?;

        common::perform_send(&mut self.send_socket, &data).await
    }
}

#[async_transform::impl_async_methods_to_impl_futures]
impl RecvConnectionHttp {
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
        let raw_message = parse_response::<S>(&data)?;
        debug!("Received raw message: {:?}", raw_message);

        Ok(raw_message)
    }
}

#[async_transform::trait_impl_async_methods_to_box_futures]
impl SendConnection for SendConnectionHttp {
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
impl RecvConnection for RecvConnectionHttp {
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
    let mut buf_recv = BufReader::new(recv);
    let mut lines = (&mut buf_recv).lines();
    debug!("Lines stream of buffered recv: {:?}", lines);

    let mut i = 0usize;
    let len = loop {
        i += 1;
        debug!("Loop iteration #{}: lines = {:?}", i, lines);

        match lines.next().await.transpose()? {
            Some(line) => {
                debug!("Polled line: line = {:?}, lines = {:?}", line, lines);

                if line.len() >= 16 && line[..16].eq_ignore_ascii_case("Content-Length: ") {
                    let len = line[16..].parse::<usize>().unwrap();
                    debug!("Content length: {}", len);
                    break len;
                }
            },
            None => panic!("HTTP response should not end here!"),  // FIXME
        }
    };

    match lines.next().await.transpose()? {
        Some(line) => assert_eq!(line, ""),
        None => panic!("HTTP response should not end here!"),  // FIXME
    }

    debug!("foo");

    let mut buf = vec![0; len];
    buf_recv.read_exact(&mut buf).await?;

    debug!("Received {} bytes from server: buffered recv = {:?}, bytes = {:?}", len, buf_recv, buf);

    Ok(buf)
}

fn prepare_send_data<R>(raw_message: &R) -> error::Result<Vec<u8>>
where
    R: RawMessageCommon,
{
    let mut send_bytes = format!("\
        POST /api HTTP/1.1\r\n\
        Connection: keep-alive\r\n\
        Content-Length: {}\r\n\
        \r\n\
    ", raw_message.size_hint()?).into_bytes();

    serde_mtproto::to_writer(&mut send_bytes, raw_message)?;

    Ok(send_bytes)
}

fn parse_response<S>(response_bytes: &[u8]) -> error::Result<S>
where
    S: RawMessageCommon,
{
    debug!("Response bytes: len = {} --- {:?}", response_bytes.len(), response_bytes);

    if let Ok(response_str) = str::from_utf8(response_bytes) {
        let response_str = response_str.trim();
        let str_len = response_str.len();

        if str_len >= 7 && &response_str[0..6] == "<html>" && &response_str[str_len-7..] == "</html>" {
            let response_str = str::from_utf8(response_bytes)?;
            error!("HTML error response:\n{}", response_str);

            if let Some(begin_pos) = response_str.find("<h1>").map(|pos| pos + "<h1>".len()) {
                if let Some(end_pos) = response_str.find("</h1>") {
                    let error_text = &response_str[begin_pos..end_pos];
                    bail!(ErrorKind::HtmlErrorText(error_text.to_owned()));
                }
            }

            bail!(ErrorKind::UnknownHtmlErrorStructure(response_str.to_owned()))
        }
    }

    let len = response_bytes.len();

    if len < 24 {
        bail!(ErrorKind::BadHtmlMessage(len));
    }

    let encrypted_data_len = S::encrypted_data_len(len);
    let seed = S::Seed::new(encrypted_data_len);

    serde_mtproto::from_bytes_seed(seed, response_bytes, &[]).map_err(Into::into)
}

use std::fmt;
use std::io;
use std::mem;
use std::net::SocketAddr;

use byteorder::{ByteOrder, LittleEndian};
use futures::{self, Future, IntoFuture, Poll};
use log;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_mtproto::{self, MtProtoSized};
use tokio_io;
use tokio_tcp::{self, TcpStream};

use ::error::{self, ErrorKind};
use ::network::connection::common::Connection;
use ::network::connection::server::TCP_SERVER_ADDRS;
use ::network::connection::tcp_common;
use ::network::state::State;
use ::tl::TLObject;
use ::tl::message::{Message, MessageCommon, MessagePlain};


#[derive(Debug)]
pub struct ConnectionTcpAbridged {
    socket: TcpStream,
    server_addr: SocketAddr,
    is_first_request: bool,
}

impl ConnectionTcpAbridged {
    pub fn connect(server_addr: SocketAddr) -> ConnectFuture {
        if log_enabled!(log::Level::Info) {
            info!("New TCP connection in abridged mode to {}", server_addr);
        }

        ConnectFuture { socket_fut: TcpStream::connect(&server_addr), server_addr }
    }

    pub fn with_default_server() -> ConnectFuture {
        Self::connect(TCP_SERVER_ADDRS[0])
    }

    pub fn request_plain<T, U>(self, state: State, request_data: T)
        -> impl Future<Item = (Self, State, U), Error = error::Error> + Send
        where T: fmt::Debug + Serialize + TLObject + Send,
              U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_request::<T, U, MessagePlain<T>, MessagePlain<U>>(state, request_data)
    }

    pub fn request<T, U>(self, state: State, request_data: T)
        -> impl Future<Item = (Self, State, U), Error = error::Error> + Send
        where T: fmt::Debug + Serialize + TLObject + Send,
              U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_request::<T, U, Message<T>, Message<U>>(state, request_data)
    }

    fn impl_request<T, U, M, N>(self, mut state: State, request_data: T)
        -> impl Future<Item = (Self, State, U), Error = error::Error> + Send
        where T: fmt::Debug + Serialize + TLObject + Send,
              U: fmt::Debug + DeserializeOwned + TLObject + Send,
              M: MessageCommon<T>,
              N: MessageCommon<U> + 'static,
    {
        state.create_message::<T, M>(request_data).into_future().and_then(|request_message| {
            debug!("Message to send: {:#?}", request_message);

            let Self { socket, server_addr, mut is_first_request } = self;
            let request_future = perform_request(&state, socket, request_message, &mut is_first_request);

            request_future.and_then(move |(socket, response_bytes)| {
                tcp_common::parse_response::<U, N>(&mut state, &response_bytes)
                    .into_future()
                    .and_then(move |msg| {
                        let conn = Self { socket, server_addr, is_first_request };
                        let response = msg.into_body();

                        futures::future::ok((conn, state, response))
                    })
            })
        })
    }
}

pub struct ConnectFuture {
    socket_fut: tokio_tcp::ConnectFuture,
    server_addr: SocketAddr,
}

impl Future for ConnectFuture {
    type Item = ConnectionTcpAbridged;
    type Error = error::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let socket = self.socket_fut.poll()?;

        Ok(socket.map(|socket| ConnectionTcpAbridged {
            socket,
            server_addr: self.server_addr,
            is_first_request: true,
        }))
    }
}

impl Connection for ConnectionTcpAbridged {
    fn request_plain<T, U>(self, state: State, request_data: T)
        -> Box<Future<Item = (Self, State, U), Error = error::Error> + Send>
        where T: fmt::Debug + Serialize + TLObject + Send,
              U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        Box::new(self.request_plain(state, request_data))
    }

    fn request<T, U>(self, state: State, request_data: T)
        -> Box<Future<Item = (Self, State, U), Error = error::Error> + Send>
        where T: fmt::Debug + Serialize + TLObject + Send,
              U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        Box::new(self.request(state, request_data))
    }
}


fn perform_request<T, M>(state: &State, socket: TcpStream, message: M, is_first_request: &mut bool)
    -> impl Future<Item = (TcpStream, Vec<u8>), Error = error::Error> + Send
where T: fmt::Debug + Serialize + TLObject,
      M: MessageCommon<T>,
{
    prepare_data(state, message, is_first_request).into_future().and_then(|data| {
        let request = tokio_io::io::write_all(socket, data);

        request.and_then(|(socket, _request_bytes)| {
            tokio_io::io::read_exact(socket, [0; 1])
        }).and_then(|(socket, byte_id)| {
            let boxed = if byte_id == [0x7f] {
                Step2Future::ByteId127(tokio_io::io::read_exact(socket, [0; 3]).map(|(socket, bytes_len)| {
                    let len = LittleEndian::read_uint(&bytes_len, 3) as usize * 4;
                    (socket, len)
                }))
            } else {
                Step2Future::ByteIdNot127(futures::future::ok((socket, byte_id[0] as usize * 4)))
            };

            boxed
        }).and_then(|(socket, len)| {
            tokio_io::io::read_exact(socket, vec![0; len])
        }).map_err(Into::into)
    })
}


enum Step2Future<F> {
    ByteId127(futures::future::Map<tokio_io::io::ReadExact<TcpStream, [u8; 3]>, F>),
    ByteIdNot127(futures::future::FutureResult<(TcpStream, usize), io::Error>),
}

impl<F> Future for Step2Future<F>
    where F: FnOnce((TcpStream, [u8; 3])) -> (TcpStream, usize)
{
    type Item = (TcpStream, usize);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        match *self {
            Step2Future::ByteId127(ref mut fut) => fut.poll(),
            Step2Future::ByteIdNot127(ref mut fut) => fut.poll(),
        }
    }
}

fn prepare_data<T, M>(state: &State, message: M, is_first_request: &mut bool)
    -> error::Result<Vec<u8>>
where T: fmt::Debug + Serialize + TLObject,
      M: MessageCommon<T>,
{
    let raw_message = message.to_raw(state.auth_raw_key(), state.version)?;

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

    serde_mtproto::to_writer(&mut buf[msg_offset..], &raw_message)?;

    Ok(buf)
}

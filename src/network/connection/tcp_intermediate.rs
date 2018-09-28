use std::fmt;
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
use ::utils::safe_uint_cast;


#[derive(Debug)]
pub struct ConnectionTcpIntermediate {
    socket: TcpStream,
    server_addr: SocketAddr,
    is_first_request: bool,
}

impl ConnectionTcpIntermediate {
    pub fn connect(server_addr: SocketAddr) -> ConnectFuture {
        if log_enabled!(log::Level::Info) {
            info!("New TCP connection in intermediate mode to {}", server_addr);
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
    type Item = ConnectionTcpIntermediate;
    type Error = error::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let socket = self.socket_fut.poll()?;

        Ok(socket.map(|socket| ConnectionTcpIntermediate {
            socket,
            server_addr: self.server_addr,
            is_first_request: true,
        }))
    }
}

impl Connection for ConnectionTcpIntermediate {
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
            tokio_io::io::read_exact(socket, [0; 4])
        }).and_then(|(socket, bytes_len)| {
            let len = LittleEndian::read_u32(&bytes_len);
            tokio_io::io::read_exact(socket, vec![0; len as usize]) // FIXME: use safe cast
        }).map_err(Into::into)
    })
}

fn prepare_data<T, M>(state: &State, message: M, is_first_request: &mut bool) -> error::Result<Vec<u8>>
where T: fmt::Debug + Serialize + TLObject,
      M: MessageCommon<T>,
{
    let raw_message = message.to_raw(state.auth_raw_key(), state.version)?;
    let data_size = raw_message.size_hint()?;

    let init: &[u8] = if mem::replace(is_first_request, false) {
        b"\xee\xee\xee\xee"
    } else {
        b""
    };

    if let Ok(data_size_u32) = safe_uint_cast::<usize, u32>(data_size) {
        let size_size = mem::size_of_val(&data_size_u32);

        // FIXME: May overflow on 32-bit systems
        let mut buf = vec![0; init.len() + size_size + data_size];
        {
            let (init_bytes, rest) = buf.split_at_mut(init.len());
            let (size_bytes, message_bytes) = rest.split_at_mut(size_size);

            init_bytes.copy_from_slice(init);
            LittleEndian::write_u32(size_bytes, data_size_u32);
            serde_mtproto::to_writer(message_bytes, &raw_message)?;
        }

        Ok(buf)
    } else {
        bail!(ErrorKind::MessageTooLong(data_size));
    }
}

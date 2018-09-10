use std::fmt;
use std::io;
use std::net::SocketAddr;

use byteorder::{ByteOrder, LittleEndian};
use futures::{self, Future, IntoFuture};
use log;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_mtproto::{self, MtProtoSized};
use tokio_io;
use tokio_tcp::TcpStream;

use ::error::{self, ErrorKind};
use ::tl::TLObject;
use ::tl::message::{Message, MessageCommon, MessagePlain};
use ::network::connection::server::TCP_SERVER_ADDRS;
use ::network::connection::tcp_common;
use ::network::state::{MessagePurpose, State};


#[derive(Debug)]
pub struct ConnectionTcpIntermediate {
    socket: TcpStream,
    server_addr: SocketAddr,
    is_first_request: bool,
}

impl ConnectionTcpIntermediate {
    pub fn new(server_addr: SocketAddr)
        -> Box<Future<Item = Self, Error = error::Error> + Send>
    {
        if log_enabled!(log::Level::Info) {
            info!("New TCP connection in intermediate mode to {}", server_addr);
        }

        Box::new(TcpStream::connect(&server_addr).map(move |socket| {
            Self { socket, server_addr, is_first_request: false }
        }).map_err(Into::into))
    }

    pub fn with_default_server()
        -> Box<Future<Item = Self, Error = error::Error> + Send>
    {
        Self::new(TCP_SERVER_ADDRS[0])
    }

    pub fn request_plain<T, U>(self, state: State, request_data: T, purpose: MessagePurpose)
        -> Box<Future<Item = (Self, State, U), Error = error::Error> + Send>
        where T: fmt::Debug + Serialize + TLObject + Send,
              U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_request::<T, U, MessagePlain<T>, MessagePlain<U>>(state, request_data, purpose)
    }

    pub fn request<T, U>(self, state: State, request_data: T, purpose: MessagePurpose)
        -> Box<Future<Item = (Self, State, U), Error = error::Error> + Send>
        where T: fmt::Debug + Serialize + TLObject + Send,
              U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_request::<T, U, Message<T>, Message<U>>(state, request_data, purpose)
    }

    fn impl_request<T, U, M, N>(self, mut state: State, request_data: T, purpose: MessagePurpose)
        -> Box<Future<Item = (Self, State, U), Error = error::Error> + Send>
        where T: fmt::Debug + Serialize + TLObject + Send,
              U: fmt::Debug + DeserializeOwned + TLObject + Send,
              M: MessageCommon<T>,
              N: MessageCommon<U> + 'static,
    {
        let request_message = tryf!(state.create_message::<T, M>(request_data, purpose));
        debug!("Message to send: {:#?}", request_message);

        let Self { socket, server_addr, mut is_first_request } = self;
        let request_future = perform_request(&state, socket, request_message, &mut is_first_request);

        Box::new(request_future.and_then(move |(socket, response_bytes)| {
            tcp_common::parse_response::<U, N>(&mut state, &response_bytes)
                .into_future()
                .and_then(move |msg| {
                    let conn = Self { socket, server_addr, is_first_request };
                    let response = msg.into_body();

                    futures::future::ok((conn, state, response))
                })
        }))
    }
}


fn perform_request<T, M>(state: &State, socket: TcpStream, message: M, is_first_request: &mut bool)
    -> Box<Future<Item = (TcpStream, Vec<u8>), Error = error::Error> + Send>
    where T: fmt::Debug + Serialize + TLObject,
          M: MessageCommon<T>,
{
    let raw_message = tryf!(message.to_raw(&state.auth_raw_key, state.version));

    let size = tryf!(raw_message.size_hint());
    let data = if size <= 0xff_ff_ff_ff {
        let mut buf = vec![0; 4 + size];

        LittleEndian::write_u32(&mut buf[0..4], size as u32);  // cast is safe here
        tryf!(serde_mtproto::to_writer(&mut buf[4..], &raw_message));

        buf
    } else {
        bailf!(ErrorKind::MessageTooLong(size));
    };

    let init: Box<Future<Item = (TcpStream, &'static [u8]), Error = io::Error> + Send> = if *is_first_request {
        *is_first_request = false;
        Box::new(tokio_io::io::write_all(socket, b"\xee\xee\xee\xee".as_ref()))
    } else {
        Box::new(futures::future::ok((socket, [].as_ref())))
    };

    let request = init.and_then(|(socket, _init_bytes)| {
        tokio_io::io::write_all(socket, data)
    });

    let response = request.and_then(|(socket, _request_bytes)| {
        tokio_io::io::read_exact(socket, [0; 4])
    }).and_then(|(socket, bytes_len)| {
        let len = LittleEndian::read_u32(&bytes_len);
        tokio_io::io::read_exact(socket, vec![0; len as usize]) // FIXME: use safe cast
    });

    Box::new(response.map_err(Into::into))
}

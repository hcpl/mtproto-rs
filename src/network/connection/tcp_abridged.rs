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
pub struct ConnectionTcpAbridged {
    socket: TcpStream,
    server_addr: SocketAddr,
    is_first_request: bool,
}

impl ConnectionTcpAbridged {
    pub fn new(server_addr: SocketAddr)
        -> Box<Future<Item = Self, Error = error::Error> + Send>
    {
        if log_enabled!(log::Level::Info) {
            info!("New TCP connection in abridged mode to {}", server_addr);
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

    let size_div_4 = tryf!(raw_message.size_hint()) / 4;  // div 4 required for abridged mode
    if size_div_4 > 0xff_ff_ff {
        bailf!(ErrorKind::MessageTooLong(size_div_4 * 4));
    }

    let data = {
        // For overall efficiency we trade code conciseness for reduced amount of dynamic
        // allocations since computation redundancy here will likely cost less than overhead of
        // consecutive allocations.
        let first_request_offset = if *is_first_request { 1 } else { 0 };
        let msg_offset = first_request_offset + if size_div_4 < 0x7f { 1 } else { 4 };

        let mut buf = vec![0; msg_offset + size_div_4 * 4];

        if *is_first_request {
            buf[0] = 0xef;
            *is_first_request = false;
        }

        if size_div_4 < 0x7f {
            buf[first_request_offset] = size_div_4 as u8;
        } else {
            let x = first_request_offset;
            buf[x] = 0x7f;
            // safe to cast here, x <= 0xff_ff_ff < u64::MAX
            LittleEndian::write_uint(&mut buf[x+1..x+4], size_div_4 as u64, 3);
        }

        tryf!(serde_mtproto::to_writer(&mut buf[msg_offset..], &raw_message));

        buf
    };

    let request = tokio_io::io::write_all(socket, data);

    let response = request.and_then(|(socket, _request_bytes)| {
        tokio_io::io::read_exact(socket, [0; 1])
    }).and_then(|(socket, byte_id)| {
        let boxed: Box<Future<Item = (TcpStream, usize), Error = io::Error> + Send> = if byte_id == [0x7f] {
            Box::new(tokio_io::io::read_exact(socket, [0; 3]).map(|(socket, bytes_len)| {
                let len = LittleEndian::read_uint(&bytes_len, 3) as usize * 4;
                (socket, len)
            }))
        } else {
            Box::new(futures::future::ok((socket, byte_id[0] as usize * 4)))
        };

        boxed
    }).and_then(|(socket, len)| {
        tokio_io::io::read_exact(socket, vec![0; len])
    });

    Box::new(response.map_err(Into::into))
}

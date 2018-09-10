use std::fmt;
use std::net::SocketAddr;

use byteorder::{ByteOrder, LittleEndian};
use crc::crc32;
use futures::{self, Future, IntoFuture};
use log;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_mtproto::{self, MtProtoSized};
use tokio_io;
use tokio_tcp::TcpStream;

use ::error::{self, ErrorKind};
use ::network::connection::common::Connection;
use ::network::connection::server::TCP_SERVER_ADDRS;
use ::network::connection::tcp_common;
use ::network::state::{MessagePurpose, State};
use ::tl::TLObject;
use ::tl::message::{Message, MessageCommon, MessagePlain};


#[derive(Debug)]
pub struct ConnectionTcpFull {
    socket: TcpStream,
    server_addr: SocketAddr,
    sent_counter: u32,
}

impl ConnectionTcpFull {
    pub fn new(server_addr: SocketAddr)
        -> Box<Future<Item = Self, Error = error::Error> + Send>
    {
        if log_enabled!(log::Level::Info) {
            info!("New TCP connection in full mode to {}", server_addr);
        }

        Box::new(TcpStream::connect(&server_addr).map(move |socket| {
            Self { socket, server_addr, sent_counter: 0 }
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

        let Self { socket, server_addr, mut sent_counter } = self;
        let request_future = perform_request(&state, socket, request_message, &mut sent_counter);

        Box::new(request_future.and_then(move |(socket, response_bytes)| {
            tcp_common::parse_response::<U, N>(&mut state, &response_bytes)
                .into_future()
                .and_then(move |msg| {
                    let conn = Self { socket, server_addr, sent_counter };
                    let response = msg.into_body();

                    futures::future::ok((conn, state, response))
                })
        }))
    }
}

impl Connection for ConnectionTcpFull {
    type Addr = SocketAddr;

    fn new(addr: SocketAddr) -> Box<Future<Item = Self, Error = error::Error> + Send> {
        Self::new(addr)
    }

    fn request_plain<T, U>(self, state: State, request_data: T, purpose: MessagePurpose)
        -> Box<Future<Item = (Self, State, U), Error = error::Error> + Send>
        where T: fmt::Debug + Serialize + TLObject + Send,
              U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.request_plain(state, request_data, purpose)
    }

    fn request<T, U>(self, state: State, request_data: T, purpose: MessagePurpose)
        -> Box<Future<Item = (Self, State, U), Error = error::Error> + Send>
        where T: fmt::Debug + Serialize + TLObject + Send,
              U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.request(state, request_data, purpose)
    }
}


fn perform_request<T, M>(state: &State, socket: TcpStream, message: M, sent_counter: &mut u32)
    -> Box<Future<Item = (TcpStream, Vec<u8>), Error = error::Error> + Send>
    where T: fmt::Debug + Serialize + TLObject,
          M: MessageCommon<T>,
{
    let raw_message = tryf!(message.to_raw(&state.auth_raw_key, state.version));

    let size = tryf!(raw_message.size_hint()) + 12;  // FIXME: May overflow on 32-bit systems
    let data = if size <= 0xff_ff_ff_ff {
        let mut buf = vec![0; size];

        LittleEndian::write_u32(&mut buf[0..4], size as u32);  // cast is safe here
        LittleEndian::write_u32(&mut buf[4..8], *sent_counter);
        tryf!(serde_mtproto::to_writer(&mut buf[8..size-4], &raw_message));

        let crc = crc32::checksum_ieee(&buf[0..size-4]);
        LittleEndian::write_u32(&mut buf[size-4..], crc);

        *sent_counter += 1;

        buf
    } else {
        bailf!(ErrorKind::MessageTooLong(size));
    };

    let request = tokio_io::io::write_all(socket, data);

    let response = request.and_then(|(socket, _request_bytes)| {
        tokio_io::io::read_exact(socket, [0; 8])
    }).then(|result|
        -> Box<Future<Item = (TcpStream, Vec<u8>), Error = error::Error> + Send>
    {
        let (socket, first_bytes) = tryf!(result);

        let len = LittleEndian::read_u32(&first_bytes[0..4]);
        let ulen = len as usize;  // FIXME: use safe cast here
        // TODO: check seq_no
        let _seq_no = LittleEndian::read_u32(&first_bytes[4..8]);

        let process_last_bytes_future = tokio_io::io::read_exact(socket, vec![0; ulen - 8])
            .map_err(Into::into)
            .and_then(move |(socket, last_bytes)|
        {
            let checksum = LittleEndian::read_u32(&last_bytes[ulen - 12..ulen - 8]);
            let mut body = last_bytes;
            body.truncate(ulen - 12);

            let mut value = 0;
            value = crc32::update(value, &crc32::IEEE_TABLE, &first_bytes[0..4]);
            value = crc32::update(value, &crc32::IEEE_TABLE, &first_bytes[4..8]);
            value = crc32::update(value, &crc32::IEEE_TABLE, &body);

            let result_future = if value == checksum {
                futures::future::ok((socket, body))
            } else {
                futures::future::err(
                    error::Error::from(ErrorKind::TcpFullModeResponseInvalidChecksum(value, checksum)))
            };

            result_future
        });

        Box::new(process_last_bytes_future)
    });

    Box::new(response)
}

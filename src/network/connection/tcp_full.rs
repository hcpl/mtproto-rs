use std::fmt;
use std::mem;
use std::net::SocketAddr;

use byteorder::{ByteOrder, LittleEndian};
use crc::crc32;
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
pub struct ConnectionTcpFull {
    socket: TcpStream,
    server_addr: SocketAddr,
    sent_counter: u32,
}

impl ConnectionTcpFull {
    pub fn connect(server_addr: SocketAddr) -> ConnectFuture {
        if log_enabled!(log::Level::Info) {
            info!("New TCP connection in full mode to {}", server_addr);
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

            let Self { socket, server_addr, mut sent_counter } = self;
            let request_future = perform_request(&state, socket, request_message, &mut sent_counter);

            request_future.and_then(move |(socket, response_bytes)| {
                tcp_common::parse_response::<U, N>(&mut state, &response_bytes)
                    .into_future()
                    .and_then(move |msg| {
                        let conn = Self { socket, server_addr, sent_counter };
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
    type Item = ConnectionTcpFull;
    type Error = error::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let socket = self.socket_fut.poll()?;

        Ok(socket.map(|socket| ConnectionTcpFull {
            socket,
            server_addr: self.server_addr,
            sent_counter: 0,
        }))
    }
}

impl Connection for ConnectionTcpFull {
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


fn perform_request<T, M>(state: &State, socket: TcpStream, message: M, sent_counter: &mut u32)
    -> impl Future<Item = (TcpStream, Vec<u8>), Error = error::Error> + Send
where T: fmt::Debug + Serialize + TLObject,
      M: MessageCommon<T>,
{
    prepare_data(state, message, sent_counter).into_future().and_then(|data| {
        let request = tokio_io::io::write_all(socket, data);

        request.and_then(|(socket, _request_bytes)| {
            tokio_io::io::read_exact(socket, [0; 8])
        }).map_err(Into::into).and_then(|(socket, first_bytes)| {
            let len = LittleEndian::read_u32(&first_bytes[0..4]);
            let ulen = len as usize;  // FIXME: use safe cast here
            // TODO: check seq_no
            let _seq_no = LittleEndian::read_u32(&first_bytes[4..8]);

            tokio_io::io::read_exact(socket, vec![0; ulen - 8])
                .map_err(Into::into)
                .and_then(move |(socket, last_bytes)| {
                    let checksum = LittleEndian::read_u32(&last_bytes[ulen - 12..ulen - 8]);
                    let mut body = last_bytes;
                    body.truncate(ulen - 12);

                    let mut value = 0;
                    value = crc32::update(value, &crc32::IEEE_TABLE, &first_bytes[0..4]);
                    value = crc32::update(value, &crc32::IEEE_TABLE, &first_bytes[4..8]);
                    value = crc32::update(value, &crc32::IEEE_TABLE, &body);

                    if value == checksum {
                        Ok((socket, body))
                    } else {
                        bail!(ErrorKind::TcpFullModeResponseInvalidChecksum(value, checksum))
                    }
                })
        })
    })
}

fn prepare_data<T, M>(state: &State, message: M, sent_counter: &mut u32) -> error::Result<Vec<u8>>
where T: fmt::Debug + Serialize + TLObject,
      M: MessageCommon<T>,
{
    let raw_message = message.to_raw(state.auth_raw_key(), state.version)?;

    const SIZE_SIZE: usize = mem::size_of::<u32>();
    const SENT_COUNTER_SIZE: usize = mem::size_of::<u32>();
    let raw_message_size = raw_message.size_hint()?;
    const CRC_SIZE: usize = mem::size_of::<u32>();

    let data_size = SIZE_SIZE + SENT_COUNTER_SIZE + raw_message_size + CRC_SIZE;  // FIXME: May overflow on 32-bit systems

    if let Ok(data_size_u32) = safe_uint_cast::<usize, u32>(data_size) {
        let mut buf = vec![0; data_size];

        {
            let (size_bytes, rest) = buf.split_at_mut(SIZE_SIZE);
            let (sent_counter_bytes, rest2) = rest.split_at_mut(SENT_COUNTER_SIZE);
            let (message_bytes, _) = rest2.split_at_mut(raw_message_size);

            LittleEndian::write_u32(size_bytes, data_size_u32);
            LittleEndian::write_u32(sent_counter_bytes, *sent_counter);
            serde_mtproto::to_writer(message_bytes, &raw_message)?;
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

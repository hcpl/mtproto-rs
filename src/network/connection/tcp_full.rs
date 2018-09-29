use std::fmt;
use std::mem;
use std::net::SocketAddr;

use byteorder::{ByteOrder, LittleEndian};
use crc::crc32;
use futures::{Future, IntoFuture};
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_mtproto::{self, MtProtoSized};
use tokio_io;
use tokio_tcp::TcpStream;

use ::error::{self, ErrorKind};
use ::network::connection::common::{SERVER_ADDRS, Connection};
use ::network::connection::tcp_common;
use ::network::state::State;
use ::tl::TLObject;
use ::tl::message::{Message, MessageCommon, MessagePlain};
use ::utils::safe_uint_cast;


#[derive(Debug)]
pub struct ConnectionTcpFull {
    socket: TcpStream,
    sent_counter: u32,
}

impl ConnectionTcpFull {
    pub fn connect(server_addr: SocketAddr)
        -> impl Future<Item = Self, Error = error::Error>
    {
        info!("New TCP connection in full mode to {}", server_addr);

        TcpStream::connect(&server_addr).map_err(Into::into).map(|socket| {
            ConnectionTcpFull { socket, sent_counter: 0 }
        })
    }

    pub fn with_default_server()
        -> impl Future<Item = Self, Error = error::Error>
    {
        Self::connect(SERVER_ADDRS[0])
    }

    pub fn request_plain<T, U>(self, state: State, request_data: T)
        -> impl Future<Item = (Self, State, U), Error = error::Error>
        where T: fmt::Debug + Serialize + TLObject + Send,
              U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_request::<T, U, MessagePlain<T>, MessagePlain<U>>(state, request_data)
    }

    pub fn request<T, U>(self, state: State, request_data: T)
        -> impl Future<Item = (Self, State, U), Error = error::Error>
        where T: fmt::Debug + Serialize + TLObject + Send,
              U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_request::<T, U, Message<T>, Message<U>>(state, request_data)
    }

    fn impl_request<T, U, M, N>(self, mut state: State, request_data: T)
        -> impl Future<Item = (Self, State, U), Error = error::Error>
        where T: fmt::Debug + Serialize + TLObject + Send,
              U: fmt::Debug + DeserializeOwned + TLObject + Send,
              M: MessageCommon<T>,
              N: MessageCommon<U> + 'static,
    {
        state.create_message::<T, M>(request_data).into_future().and_then(|request_message| {
            debug!("Message to send: {:#?}", request_message);

            let Self { socket, mut sent_counter } = self;
            let request_future = perform_request(&state, socket, request_message, &mut sent_counter);

            request_future.and_then(move |(socket, response_bytes)| {
                tcp_common::parse_response::<U, N>(&mut state, &response_bytes)
                    .into_future()
                    .map(move |msg| {
                        let conn = Self { socket, sent_counter };
                        let response = msg.into_body();

                        (conn, state, response)
                    })
            })
        })
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
    -> impl Future<Item = (TcpStream, Vec<u8>), Error = error::Error>
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

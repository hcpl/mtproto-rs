use std::fmt;
use std::mem;
use std::net::SocketAddr;

use byteorder::{ByteOrder, LittleEndian};
use error_chain::bail;
use futures::{self, Future};
use futures::future::Either;
use log::{debug, info};
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_mtproto;
use tokio_io::{self, AsyncRead};
use tokio_tcp::TcpStream;

use crate::async_io;
use crate::error::{self, ErrorKind};
use crate::network::connection::common::{
    self, DEFAULT_SERVER_ADDR, Connection, RecvConnection, SendConnection,
};
use crate::network::connection::tcp_common;
use crate::network::state::State;
use crate::tl::TLObject;
use crate::tl::message::{Message, MessageCommon, MessagePlain, RawMessageCommon};


#[derive(Debug)]
pub struct ConnectionTcpAbridged {
    socket: TcpStream,
    is_first_request: bool,
}

impl ConnectionTcpAbridged {
    pub fn connect(server_addr: SocketAddr)
        -> impl Future<Item = Self, Error = error::Error>
    {
        info!("New TCP connection in abridged mode to {}", server_addr);

        TcpStream::connect(&server_addr).map_err(Into::into).map(|socket| {
            Self { socket, is_first_request: true }
        })
    }

    pub fn with_default_server()
        -> impl Future<Item = Self, Error = error::Error>
    {
        Self::connect(*DEFAULT_SERVER_ADDR)
    }

    pub fn send_plain<T>(self, state: State, send_data: T)
        -> impl Future<Item = (Self, State), Error = (Self, State, T, error::Error)>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
    {
        self.impl_send::<T, MessagePlain<T>>(state, send_data)
    }

    pub fn send<T>(self, state: State, send_data: T)
        -> impl Future<Item = (Self, State), Error = (Self, State, T, error::Error)>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
    {
        self.impl_send::<T, Message<T>>(state, send_data)
    }

    fn impl_send<T, M>(self, mut state: State, send_data: T)
        -> impl Future<Item = (Self, State), Error = (Self, State, T, error::Error)>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        M: MessageCommon<T>,
    {
        match state.create_message2::<T, M>(send_data) {
            Err((send_data, e)) => {
                futures::future::Either::A(futures::future::err((self, state, send_data, e)))
            },
            Ok(request_message) => {
                debug!("Message to send: {:?}", request_message);

                match request_message.to_raw(state.auth_raw_key(), state.version) {
                    Err(e) => {
                        let send_data = request_message.into_body();
                        futures::future::Either::A(futures::future::err((self, state, send_data, e)))
                    },
                    Ok(raw_message) => {
                        futures::future::Either::B(self.send_raw(raw_message).then(|res| match res {
                            Err((conn, _, e)) => Err((conn, state, request_message.into_body(), e)),
                            Ok(conn) => Ok((conn, state)),
                        }))
                    },
                }
            },
        }
    }

    pub fn send_raw<R>(mut self, raw_message: R)
        -> impl Future<Item = Self, Error = (Self, R, error::Error)>
    where
        R: RawMessageCommon,
    {
        debug!("Raw message to send: {:?}", raw_message);

        match prepare_send_data(&raw_message, &mut self.is_first_request) {
            Err(e) => futures::future::Either::A(futures::future::err((self, raw_message, e))),
            Ok(data) => {
                let Self { socket, is_first_request } = self;

                futures::future::Either::B(common::perform_send(socket, data)
                    .map(move |socket| Self { socket, is_first_request })
                    .map_err(move |(socket, _, e)| {
                        (Self { socket, is_first_request }, raw_message, e)
                    }))
            },
        }
    }

    pub fn recv_plain<U>(self, state: State)
        -> impl Future<Item = (Self, State, U), Error = (Self, State, error::Error)>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_recv::<U, MessagePlain<U>>(state)
    }

    pub fn recv<U>(self, state: State)
        -> impl Future<Item = (Self, State, U), Error = (Self, State, error::Error)>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_recv::<U, Message<U>>(state)
    }

    fn impl_recv<U, N>(self, state: State)
        -> impl Future<Item = (Self, State, U), Error = (Self, State, error::Error)>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
        N: MessageCommon<U>,
    {
        self.recv_raw().then(|res| match res {
            Err((conn, e)) => Err((conn, state, e)),
            Ok((conn, raw_message)) => match common::from_raw::<U, N>(&raw_message, &state) {
                Err(e) => Err((conn, state, e)),
                Ok(message) => {
                    debug!("Received message: {:?}", message);
                    Ok((conn, state, message.into_body()))
                }
            },
        })
    }

    pub fn recv_raw<S>(self)
        -> impl Future<Item = (Self, S), Error = (Self, error::Error)>
    where
        S: RawMessageCommon,
    {
        let Self { socket, is_first_request } = self;

        perform_recv(socket)
            .map_err(move |(socket, e)| (Self { socket, is_first_request }, e))
            .and_then(move |(socket, data)| {
                let conn = Self { socket, is_first_request };

                match tcp_common::parse_response::<S>(&data) {
                    Ok(raw_message) => {
                        debug!("Received raw message: {:?}", raw_message);
                        Ok((conn, raw_message))
                    },
                    Err(e) => Err((conn, e)),
                }
            })
    }

    pub fn request_plain<T, U>(self, state: State, request_data: T)
        -> impl Future<Item = (Self, State, U), Error = (Self, State, Option<T>, error::Error)>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_request::<T, U, MessagePlain<T>, MessagePlain<U>>(state, request_data)
    }

    pub fn request<T, U>(self, state: State, request_data: T)
        -> impl Future<Item = (Self, State, U), Error = (Self, State, Option<T>, error::Error)>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_request::<T, U, Message<T>, Message<U>>(state, request_data)
    }

    fn impl_request<T, U, M, N>(self, state: State, request_data: T)
        -> impl Future<Item = (Self, State, U), Error = (Self, State, Option<T>, error::Error)>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
        M: MessageCommon<T>,
        N: MessageCommon<U> + 'static,
    {
        self.impl_send::<T, M>(state, request_data)
            .map_err(|(conn, state, request_data, e)| (conn, state, Some(request_data), e))
            .and_then(|(conn, state)| {
                conn.impl_recv::<U, N>(state).map_err(|(conn, state, e)| (conn, state, None, e))
            })
    }
}

impl Connection for ConnectionTcpAbridged {
    type SendConnection = SendConnectionTcpAbridged;
    type RecvConnection = RecvConnectionTcpAbridged;

    fn connect(server_addr: SocketAddr)
        -> Box<dyn Future<Item = Self, Error = error::Error> + Send>
    {
        Box::new(Self::connect(server_addr))
    }

    fn with_default_server()
        -> Box<dyn Future<Item = Self, Error = error::Error> + Send>
    {
        Box::new(Self::with_default_server())
    }

    fn request_plain<T, U>(self, state: State, request_data: T)
        -> Box<dyn Future<Item = (Self, State, U), Error = (Self, State, Option<T>, error::Error)> + Send>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        Box::new(self.request_plain(state, request_data))
    }

    fn request<T, U>(self, state: State, request_data: T)
        -> Box<dyn Future<Item = (Self, State, U), Error = (Self, State, Option<T>, error::Error)> + Send>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        Box::new(self.request(state, request_data))
    }

    fn split(self) -> (Self::SendConnection, Self::RecvConnection) {
        self.split()
    }
}


#[derive(Debug)]
pub struct SendConnectionTcpAbridged {
    send_socket: tokio_io::io::WriteHalf<TcpStream>,
    is_first_request: bool,
}

#[derive(Debug)]
pub struct RecvConnectionTcpAbridged {
    recv_socket: tokio_io::io::ReadHalf<TcpStream>,
}

impl ConnectionTcpAbridged {
    pub fn split(self) -> (SendConnectionTcpAbridged, RecvConnectionTcpAbridged) {
        let Self { socket, is_first_request } = self;
        let (recv_socket, send_socket) = socket.split();

        (
            SendConnectionTcpAbridged { send_socket, is_first_request },
            RecvConnectionTcpAbridged { recv_socket },
        )
    }
}

impl SendConnectionTcpAbridged {
    pub fn send_plain<T>(self, state: State, send_data: T)
        -> impl Future<Item = (Self, State), Error = (Self, State, T, error::Error)>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
    {
        self.impl_send::<T, MessagePlain<T>>(state, send_data)
    }

    pub fn send<T>(self, state: State, send_data: T)
        -> impl Future<Item = (Self, State), Error = (Self, State, T, error::Error)>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
    {
        self.impl_send::<T, Message<T>>(state, send_data)
    }

    fn impl_send<T, M>(self, mut state: State, send_data: T)
        -> impl Future<Item = (Self, State), Error = (Self, State, T, error::Error)>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        M: MessageCommon<T>,
    {
        match state.create_message2::<T, M>(send_data) {
            Err((send_data, e)) => {
                futures::future::Either::A(futures::future::err((self, state, send_data, e)))
            },
            Ok(request_message) => {
                debug!("Message to send: {:?}", request_message);

                match request_message.to_raw(state.auth_raw_key(), state.version) {
                    Err(e) => {
                        let send_data = request_message.into_body();
                        futures::future::Either::A(futures::future::err((self, state, send_data, e)))
                    },
                    Ok(raw_message) => {
                        futures::future::Either::B(self.send_raw(raw_message).then(|res| match res {
                            Err((conn, _, e)) => Err((conn, state, request_message.into_body(), e)),
                            Ok(conn) => Ok((conn, state)),
                        }))
                    },
                }
            },
        }
    }

    pub fn send_raw<R>(mut self, raw_message: R)
        -> impl Future<Item = Self, Error = (Self, R, error::Error)>
    where
        R: RawMessageCommon,
    {
        debug!("Raw message to send: {:?}", raw_message);

        match prepare_send_data(&raw_message, &mut self.is_first_request) {
            Err(e) => futures::future::Either::A(futures::future::err((self, raw_message, e))),
            Ok(data) => {
                let Self { send_socket, is_first_request } = self;

                futures::future::Either::B(common::perform_send(send_socket, data)
                    .map(move |send_socket| Self { send_socket, is_first_request })
                    .map_err(move |(send_socket, _, e)| {
                        (Self { send_socket, is_first_request }, raw_message, e)
                    }))
            },
        }
    }
}

impl RecvConnectionTcpAbridged {
    pub fn recv_plain<U>(self, state: State)
        -> impl Future<Item = (Self, State, U), Error = (Self, State, error::Error)>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_recv::<U, MessagePlain<U>>(state)
    }

    pub fn recv<U>(self, state: State)
        -> impl Future<Item = (Self, State, U), Error = (Self, State, error::Error)>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_recv::<U, Message<U>>(state)
    }

    fn impl_recv<U, N>(self, state: State)
        -> impl Future<Item = (Self, State, U), Error = (Self, State, error::Error)>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
        N: MessageCommon<U>,
    {
        self.recv_raw().then(|res| match res {
            Err((conn, e)) => Err((conn, state, e)),
            Ok((conn, raw_message)) => match common::from_raw::<U, N>(&raw_message, &state) {
                Err(e) => Err((conn, state, e)),
                Ok(message) => {
                    debug!("Received message: {:?}", message);
                    Ok((conn, state, message.into_body()))
                }
            },
        })
    }

    pub fn recv_raw<S>(self)
        -> impl Future<Item = (Self, S), Error = (Self, error::Error)>
    where
        S: RawMessageCommon,
    {
        let Self { recv_socket } = self;

        perform_recv(recv_socket)
            .map_err(|(recv_socket, e)| (Self { recv_socket }, e))
            .and_then(|(recv_socket, data)| {
                let conn = Self { recv_socket };

                match tcp_common::parse_response::<S>(&data) {
                    Ok(raw_message) => {
                        debug!("Received raw message: {:?}", raw_message);
                        Ok((conn, raw_message))
                    },
                    Err(e) => Err((conn, e)),
                }
            })
    }
}

impl SendConnection for SendConnectionTcpAbridged {
    fn send_plain<T>(self, state: State, send_data: T)
        -> Box<dyn Future<Item = (Self, State), Error = (Self, State, T, error::Error)> + Send>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
    {
        Box::new(self.send_plain(state, send_data))
    }

    fn send<T>(self, state: State, send_data: T)
        -> Box<dyn Future<Item = (Self, State), Error = (Self, State, T, error::Error)> + Send>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
    {
        Box::new(self.send(state, send_data))
    }

    fn send_raw<R>(self, raw_message: R)
        -> Box<dyn Future<Item = Self, Error = (Self, R, error::Error)> + Send>
    where
        R: RawMessageCommon,
    {
        Box::new(self.send_raw(raw_message))
    }
}

impl RecvConnection for RecvConnectionTcpAbridged {
    fn recv_plain<U>(self, state: State)
        -> Box<dyn Future<Item = (Self, State, U), Error = (Self, State, error::Error)> + Send>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        Box::new(self.recv_plain(state))
    }

    fn recv<U>(self, state: State)
        -> Box<dyn Future<Item = (Self, State, U), Error = (Self, State, error::Error)> + Send>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        Box::new(self.recv(state))
    }

    fn recv_raw<S>(self)
        -> Box<dyn Future<Item = (Self, S), Error = (Self, error::Error)> + Send>
    where
        S: RawMessageCommon,
    {
        Box::new(self.recv_raw())
    }
}


fn perform_recv<R>(recv: R)
    -> impl Future<Item = (R, Vec<u8>), Error = (R, error::Error)>
where
    R: fmt::Debug + AsyncRead,
{
    async_io::read_exact(recv, [0; 1]).and_then(|(recv, byte_id)| {
        debug!("Received {} bytes from server: recv = {:?}, bytes = {:?}",
            byte_id.len(), recv, byte_id);

        if byte_id == [0x7f] {
            Either::A(async_io::read_exact(recv, [0; 3]).map(|(recv, bytes_len)| {
                debug!("Received {} bytes from server: recv = {:?}, bytes = {:?}",
                    bytes_len.len(), recv, bytes_len);

                let len = LittleEndian::read_uint(&bytes_len, 3) as usize * 4;
                (recv, len)
            }))
        } else {
            Either::B(futures::future::ok((recv, byte_id[0] as usize * 4)))
        }
    }).and_then(|(recv, len)| {
        debug!("Got length from server: recv = {:?}, length = {}", recv, len);
        async_io::read_exact(recv, vec![0; len])
    }).map_err(|(recv, e)| (recv, common::convert_read_io_error(e)))
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

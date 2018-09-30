use std::fmt;
use std::mem;
use std::net::SocketAddr;

use byteorder::{ByteOrder, LittleEndian};
use futures::{Future, IntoFuture};
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_mtproto::{self, MtProtoSized};
use tokio_io::{self, AsyncRead};
use tokio_tcp::TcpStream;

use ::error::{self, ErrorKind};
use ::network::connection::common::{self, SERVER_ADDRS, Connection};
use ::network::connection::tcp_common;
use ::network::state::State;
use ::tl::TLObject;
use ::tl::message::{Message, MessageCommon, MessagePlain};
use ::utils::safe_uint_cast;


#[derive(Debug)]
pub struct ConnectionTcpIntermediate {
    socket: TcpStream,
    is_first_request: bool,
}

impl ConnectionTcpIntermediate {
    pub fn connect(server_addr: SocketAddr)
        -> impl Future<Item = Self, Error = error::Error>
    {
        info!("New TCP connection in intermediate mode to {}", server_addr);

        TcpStream::connect(&server_addr).map_err(Into::into).map(|socket| {
            Self { socket, is_first_request: true }
        })
    }

    pub fn with_default_server()
        -> impl Future<Item = Self, Error = error::Error>
    {
        Self::connect(SERVER_ADDRS[0])
    }

    pub fn send_plain<T>(self, state: State, send_data: T)
        -> impl Future<Item = (Self, State), Error = error::Error>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
    {
        self.impl_send::<T, MessagePlain<T>>(state, send_data)
    }

    pub fn send<T>(self, state: State, send_data: T)
        -> impl Future<Item = (Self, State), Error = error::Error>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
    {
        self.impl_send::<T, Message<T>>(state, send_data)
    }

    fn impl_send<T, M>(self, mut state: State, send_data: T)
        -> impl Future<Item = (Self, State), Error = error::Error>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        M: MessageCommon<T>,
    {
        state.create_message::<T, M>(send_data).into_future().and_then(|request_message| {
            debug!("Message to send: {:?}", request_message);

            let Self { socket, mut is_first_request } = self;

            prepare_send_data::<T, M>(&state, request_message, &mut is_first_request)
                .into_future()
                .and_then(|data| common::perform_send(socket, data))
                .map(move |socket| (Self { socket, is_first_request }, state))
        })
    }

    pub fn recv_plain<U>(self, state: State)
        -> impl Future<Item = (Self, State, U), Error = error::Error>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_recv::<U, MessagePlain<U>>(state)
    }

    pub fn recv<U>(self, state: State)
        -> impl Future<Item = (Self, State, U), Error = error::Error>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_recv::<U, Message<U>>(state)
    }

    fn impl_recv<U, N>(self, state: State)
        -> impl Future<Item = (Self, State, U), Error = error::Error>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
        N: MessageCommon<U>,
    {
        let Self { socket, is_first_request } = self;

        perform_recv(socket).and_then(move |(socket, data)| {
            tcp_common::parse_response::<U, N>(&state, &data).into_future().map(move |msg| {
                debug!("Received message: {:?}", msg);

                let conn = Self { socket, is_first_request };
                let response = msg.into_body();

                (conn, state, response)
            })
        })
    }

    pub fn request_plain<T, U>(self, state: State, request_data: T)
        -> impl Future<Item = (Self, State, U), Error = error::Error>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_request::<T, U, MessagePlain<T>, MessagePlain<U>>(state, request_data)
    }

    pub fn request<T, U>(self, state: State, request_data: T)
        -> impl Future<Item = (Self, State, U), Error = error::Error>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_request::<T, U, Message<T>, Message<U>>(state, request_data)
    }

    fn impl_request<T, U, M, N>(self, state: State, request_data: T)
        -> impl Future<Item = (Self, State, U), Error = error::Error>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
        M: MessageCommon<T>,
        N: MessageCommon<U> + 'static,
    {
        self.impl_send::<T, M>(state, request_data).and_then(|(conn, state)| {
            conn.impl_recv::<U, N>(state)
        })
    }
}

impl Connection for ConnectionTcpIntermediate {
    fn request_plain<T, U>(self, state: State, request_data: T)
        -> Box<Future<Item = (Self, State, U), Error = error::Error> + Send>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        Box::new(self.request_plain(state, request_data))
    }

    fn request<T, U>(self, state: State, request_data: T)
        -> Box<Future<Item = (Self, State, U), Error = error::Error> + Send>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        Box::new(self.request(state, request_data))
    }
}


#[derive(Debug)]
pub struct SendConnectionTcpIntermediate {
    send_socket: tokio_io::io::WriteHalf<TcpStream>,
    is_first_request: bool,
}

#[derive(Debug)]
pub struct RecvConnectionTcpIntermediate {
    recv_socket: tokio_io::io::ReadHalf<TcpStream>,
}

impl ConnectionTcpIntermediate {
    pub fn split(self) -> (SendConnectionTcpIntermediate, RecvConnectionTcpIntermediate) {
        let Self { socket, is_first_request } = self;
        let (recv_socket, send_socket) = socket.split();

        (
            SendConnectionTcpIntermediate { send_socket, is_first_request },
            RecvConnectionTcpIntermediate { recv_socket },
        )
    }
}

impl SendConnectionTcpIntermediate {
    pub fn send_plain<T>(self, state: State, send_data: T)
        -> impl Future<Item = (Self, State), Error = error::Error>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
    {
        self.impl_send::<T, MessagePlain<T>>(state, send_data)
    }

    pub fn send<T>(self, state: State, send_data: T)
        -> impl Future<Item = (Self, State), Error = error::Error>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
    {
        self.impl_send::<T, Message<T>>(state, send_data)
    }

    fn impl_send<T, M>(self, mut state: State, send_data: T)
        -> impl Future<Item = (Self, State), Error = error::Error>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        M: MessageCommon<T>,
    {
        state.create_message::<T, M>(send_data).into_future().and_then(|request_message| {
            debug!("Message to send: {:?}", request_message);

            let Self { send_socket, mut is_first_request } = self;

            prepare_send_data::<T, M>(&state, request_message, &mut is_first_request)
                .into_future()
                .and_then(|data| common::perform_send(send_socket, data))
                .map(move |send_socket| (Self { send_socket, is_first_request }, state))
        })
    }
}

impl RecvConnectionTcpIntermediate {
    pub fn recv_plain<U>(self, state: State)
        -> impl Future<Item = (Self, State, U), Error = error::Error>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_recv::<U, MessagePlain<U>>(state)
    }

    pub fn recv<U>(self, state: State)
        -> impl Future<Item = (Self, State, U), Error = error::Error>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_recv::<U, Message<U>>(state)
    }

    fn impl_recv<U, N>(self, state: State)
        -> impl Future<Item = (Self, State, U), Error = error::Error>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
        N: MessageCommon<U>,
    {
        let Self { recv_socket } = self;

        perform_recv(recv_socket).and_then(move |(recv_socket, data)| {
            tcp_common::parse_response::<U, N>(&state, &data).into_future().map(move |msg| {
                debug!("Received message: {:?}", msg);

                let conn = Self { recv_socket };
                let response = msg.into_body();

                (conn, state, response)
            })
        })
    }
}


fn perform_recv<R>(recv: R) -> impl Future<Item = (R, Vec<u8>), Error = error::Error>
where
    R: fmt::Debug + AsyncRead,
{
    tokio_io::io::read_exact(recv, [0; 4]).and_then(|(recv, bytes_len)| {
        debug!("Received {} bytes from server: recv = {:?}, bytes = {:?}",
            bytes_len.len(), recv, bytes_len);

        let len = LittleEndian::read_u32(&bytes_len);
        tokio_io::io::read_exact(recv, vec![0; len as usize]) // FIXME: use safe cast
    }).map_err(Into::into)
}

fn prepare_send_data<T, M>(state: &State, message: M, is_first_request: &mut bool)
    -> error::Result<Vec<u8>>
where
    T: fmt::Debug + Serialize + TLObject,
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

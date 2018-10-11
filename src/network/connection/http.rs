use std::fmt;
use std::io::BufReader;
use std::net::SocketAddr;
use std::str;

use futures::{self, Future, Stream};
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_mtproto;
use tokio_io::{self, AsyncRead};
use tokio_tcp::TcpStream;

use ::async_io;
use ::error::{self, ErrorKind};
use ::network::connection::common::{self, SERVER_ADDRS, Connection, RecvConnection, SendConnection};
use ::network::state::State;
use ::tl::TLObject;
use ::tl::message::{Message, MessageCommon, MessagePlain, RawMessageCommon, RawMessageSeedCommon};


pub struct ConnectionHttp {
    socket: TcpStream,
}

impl ConnectionHttp {
    pub fn connect(server_addr: SocketAddr)
        -> impl Future<Item = Self, Error = error::Error>
    {
        info!("New HTTP connection to {}", server_addr);

        TcpStream::connect(&server_addr).map_err(Into::into).map(move |socket| {
            Self { socket }
        })
    }

    pub fn with_default_server()
        -> impl Future<Item = ConnectionHttp, Error = error::Error>
    {
        Self::connect(SERVER_ADDRS[0])
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
        match state.create_message::<T, M>(send_data) {
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

    pub fn send_raw<R>(self, raw_message: R)
        -> impl Future<Item = Self, Error = (Self, R, error::Error)>
    where
        R: RawMessageCommon,
    {
        debug!("Raw message to send: {:?}", raw_message);

        match prepare_send_data(&raw_message) {
            Err(e) => futures::future::Either::A(futures::future::err((self, raw_message, e))),
            Ok(data) => {
                let Self { socket } = self;

                futures::future::Either::B(common::perform_send(socket, data)
                    .map(|socket| Self { socket })
                    .map_err(|(socket, _, e)| {
                        (Self { socket }, raw_message, e)
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
        let Self { socket } = self;

        perform_recv(socket)
            .map_err(|(socket, e)| (Self { socket }, e))
            .and_then(|(socket, data)| {
                let conn = Self { socket };

                match parse_response::<S>(&data) {
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

impl Connection for ConnectionHttp {
    type SendConnection = SendConnectionHttp;
    type RecvConnection = RecvConnectionHttp;

    fn connect(server_addr: SocketAddr)
        -> Box<Future<Item = Self, Error = error::Error> + Send>
    {
        Box::new(Self::connect(server_addr))
    }

    fn with_default_server()
        -> Box<Future<Item = Self, Error = error::Error> + Send>
    {
        Box::new(Self::with_default_server())
    }

    fn request_plain<T, U>(self, state: State, request_data: T)
        -> Box<Future<Item = (Self, State, U), Error = (Self, State, Option<T>, error::Error)> + Send>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        Box::new(self.request_plain(state, request_data))
    }

    fn request<T, U>(self, state: State, request_data: T)
        -> Box<Future<Item = (Self, State, U), Error = (Self, State, Option<T>, error::Error)> + Send>
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
pub struct SendConnectionHttp {
    send_socket: tokio_io::io::WriteHalf<TcpStream>,
}

#[derive(Debug)]
pub struct RecvConnectionHttp {
    recv_socket: tokio_io::io::ReadHalf<TcpStream>,
}

impl ConnectionHttp {
    pub fn split(self) -> (SendConnectionHttp, RecvConnectionHttp) {
        let Self { socket } = self;
        let (recv_socket, send_socket) = socket.split();

        (
            SendConnectionHttp { send_socket },
            RecvConnectionHttp { recv_socket },
        )
    }
}

impl SendConnectionHttp {
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
        match state.create_message::<T, M>(send_data) {
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

    pub fn send_raw<R>(self, raw_message: R)
        -> impl Future<Item = Self, Error = (Self, R, error::Error)>
    where
        R: RawMessageCommon,
    {
        debug!("Raw message to send: {:?}", raw_message);

        match prepare_send_data(&raw_message) {
            Err(e) => futures::future::Either::A(futures::future::err((self, raw_message, e))),
            Ok(data) => {
                let Self { send_socket } = self;

                futures::future::Either::B(common::perform_send(send_socket, data)
                    .map(move |send_socket| Self { send_socket })
                    .map_err(move |(send_socket, _, e)| {
                        (Self { send_socket }, raw_message, e)
                    }))
            },
        }
    }
}

impl RecvConnectionHttp {
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

                match parse_response::<S>(&data) {
                    Ok(raw_message) => {
                        debug!("Received raw message: {:?}", raw_message);
                        Ok((conn, raw_message))
                    },
                    Err(e) => Err((conn, e)),
                }
            })
    }
}

impl SendConnection for SendConnectionHttp {
    fn send_plain<T>(self, state: State, send_data: T)
        -> Box<Future<Item = (Self, State), Error = (Self, State, T, error::Error)> + Send>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
    {
        Box::new(self.send_plain(state, send_data))
    }

    fn send<T>(self, state: State, send_data: T)
        -> Box<Future<Item = (Self, State), Error = (Self, State, T, error::Error)> + Send>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
    {
        Box::new(self.send(state, send_data))
    }

    fn send_raw<R>(self, raw_message: R)
        -> Box<Future<Item = Self, Error = (Self, R, error::Error)> + Send>
    where
        R: RawMessageCommon,
    {
        Box::new(self.send_raw(raw_message))
    }
}

impl RecvConnection for RecvConnectionHttp {
    fn recv_plain<U>(self, state: State)
        -> Box<Future<Item = (Self, State, U), Error = (Self, State, error::Error)> + Send>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        Box::new(self.recv_plain(state))
    }

    fn recv<U>(self, state: State)
        -> Box<Future<Item = (Self, State, U), Error = (Self, State, error::Error)> + Send>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        Box::new(self.recv(state))
    }

    fn recv_raw<S>(self)
        -> Box<Future<Item = (Self, S), Error = (Self, error::Error)> + Send>
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
    let lines = async_io::lines(BufReader::new(recv));

    debug!("Lines stream of buffered recv: {:?}", lines);

    futures::future::loop_fn((0usize, lines), |(i, lines)| {
        debug!("Loop fn iteration #{}: lines = {:?}", i, lines);

        lines.into_future().map(move |(line, lines)| {
            debug!("Polled line: line = {:?}, lines = {:?}", line, lines);

            match line {
                Some(line) => {
                    if line.len() >= 16 && line[..16].eq_ignore_ascii_case("Content-Length: ") {
                        let len = line[16..].parse::<usize>().unwrap();
                        debug!("Content length: {}", len);

                        return futures::future::Loop::Break((lines, len));
                    }

                    futures::future::Loop::Continue((i + 1, lines))
                },
                None => panic!("HTTP response should not end here!"),  // FIXME
            }
        })
    }).and_then(|(lines, len)| {
        lines.into_future().map(move |(line, lines)| {
            assert_eq!(line.unwrap(), "");
            (lines, len)
        })
    }).map_err(|((buf_recv, e), _)| {
        (buf_recv, e)
    }).and_then(|(lines, len)| {
        async_io::read_exact(lines.into_inner(), vec![0; len]).map(|(buf_recv, body)| {
            debug!("Received {} bytes from server: recv = {:?}, bytes = {:?}",
                body.len(), buf_recv, body);

            (buf_recv.into_inner(), body)
        }).map_err(|(recv, e)| (recv, e))
    }).map_err(|(buf_recv, e)| (buf_recv.into_inner(), e.into()))
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

use std::fmt;
use std::io::BufReader;
use std::net::SocketAddr;
use std::str;

use futures::{self, Future, IntoFuture, Stream};
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_mtproto::{self, MtProtoSized};
use tokio_io::{self, AsyncRead};
use tokio_tcp::TcpStream;

use ::error::{self, ErrorKind};
use ::network::connection::common::{self, SERVER_ADDRS, Connection};
use ::network::state::State;
use ::tl::TLObject;
use ::tl::message::{Message, MessageCommon, MessagePlain, RawMessageSeedCommon};


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

            let Self { socket } = self;

            prepare_send_data::<T, M>(&state, request_message)
                .into_future()
                .and_then(|data| common::perform_send(socket, data))
                .map(move |socket| (Self { socket }, state))
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
        let Self { socket } = self;

        perform_recv(socket).and_then(move |(socket, data)| {
            parse_response::<U, N>(&state, &data).into_future().map(move |msg| {
                debug!("Received message: {:?}", msg);

                let conn = Self { socket };
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

impl Connection for ConnectionHttp {
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

            let Self { send_socket } = self;

            prepare_send_data::<T, M>(&state, request_message)
                .into_future()
                .and_then(|data| common::perform_send(send_socket, data))
                .map(move |send_socket| (Self { send_socket }, state))
        })
    }
}

impl RecvConnectionHttp {
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
            parse_response::<U, N>(&state, &data).into_future().map(move |msg| {
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
    let lines = tokio_io::io::lines(BufReader::new(recv));

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
    }).map_err(|(e, _)| e).and_then(|(lines, len)| {
        tokio_io::io::read_exact(lines.into_inner(), vec![0; len]).map(|(buf_recv, body)| {
            debug!("Received {} bytes from server: recv = {:?}, bytes = {:?}",
                body.len(), buf_recv, body);

            (buf_recv.into_inner(), body)
        })
    }).map_err(Into::into)
}

fn prepare_send_data<T, M>(state: &State, message: M)
    -> error::Result<Vec<u8>>
where
    T: fmt::Debug + Serialize + TLObject,
    M: MessageCommon<T>,
{
    let raw_message = message.to_raw(state.auth_raw_key(), state.version)?;

    let mut send_bytes = format!("\
        POST /api HTTP/1.1\r\n\
        Connection: keep-alive\r\n\
        Content-Length: {}\r\n\
        \r\n\
    ", raw_message.size_hint()?).into_bytes();

    serde_mtproto::to_writer(&mut send_bytes, &raw_message)?;

    Ok(send_bytes)
}

fn parse_response<U, N>(state: &State, response_bytes: &[u8]) -> error::Result<N>
    where U: fmt::Debug + DeserializeOwned + TLObject,
          N: MessageCommon<U>,
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

    let encrypted_data_len = N::encrypted_data_len(len);

    macro_rules! deserialize_response {
        ($vnames:expr) => {{
            serde_mtproto::from_bytes_seed(N::RawSeed::new(encrypted_data_len), response_bytes, $vnames)
                .map_err(Into::into)
                .and_then(|raw| N::from_raw(raw, state.auth_raw_key(), state.version, $vnames))
        }};
    }

    if let Some(variant_names) = U::all_enum_variant_names() {
        // FIXME: Lossy error management
        for vname in variant_names {
            if let Ok(msg) = deserialize_response!(&[vname]) {
                return Ok(msg);
            }
        }

        bail!(ErrorKind::BadTcpMessage(len))
    } else {
        deserialize_response!(&[])
    }
}

use std::fmt;
use std::io::BufReader;
use std::str;

use error_chain::bail;
use futures::{Future, Stream};
use log::{debug, error};
use tokio_io::AsyncRead;
use tokio_tcp::TcpStream;

use crate::async_io;
use crate::error::{self, ErrorKind};
use crate::network::connection::common;
use crate::tl::message::{RawMessageCommon, RawMessageSeedCommon};


pub struct ConnectionHttp {
    socket: TcpStream,
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

    generate_create_connection_methods!(
        connection_log_str = "HTTP connection",
        ret = |socket| Self { socket },
    );

    generate_send_connection_methods!();
    generate_send_raw_method!(
        prepare_send_data = |raw_message, _self| prepare_send_data(raw_message),
        perform_send = |socket, data| common::perform_send(socket, data),
        self_to_fields = |self_: Self| (self_.socket, ()),
        self_from_fields = |socket, ()| Self { socket },
    );

    generate_recv_connection_methods!();
    generate_recv_raw_method!(
        parse_response = |data| parse_response::<S>(data),
        self_to_fields = |self_: Self| (self_.socket, ()),
        self_from_fields = |socket, ()| Self { socket },
    );

    generate_request_connection_methods!();
}

delegate_impl_connection_for!(ConnectionHttp with
    SendConnection = SendConnectionHttp,
    RecvConnection = RecvConnectionHttp);


#[derive(Debug)]
pub struct SendConnectionHttp {
    send_socket: tokio_io::io::WriteHalf<TcpStream>,
}

impl SendConnectionHttp {
    generate_send_connection_methods!();
    generate_send_raw_method!(
        prepare_send_data = |raw_message, _self| prepare_send_data(raw_message),
        perform_send = |send_socket, data| common::perform_send(send_socket, data),
        self_to_fields = |self_: Self| (self_.send_socket, ()),
        self_from_fields = |send_socket, ()| Self { send_socket },
    );
}

delegate_impl_send_connection_for!(SendConnectionHttp);


#[derive(Debug)]
pub struct RecvConnectionHttp {
    recv_socket: tokio_io::io::ReadHalf<TcpStream>,
}

impl RecvConnectionHttp {
    generate_recv_connection_methods!();
    generate_recv_raw_method!(
        parse_response = |data| parse_response::<S>(data),
        self_to_fields = |self_: Self| (self_.recv_socket, ()),
        self_from_fields = |recv_socket, ()| Self { recv_socket },
    );
}

delegate_impl_recv_connection_for!(RecvConnectionHttp);


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
            debug!("Received {} bytes from server: buffered recv = {:?}, bytes = {:?}",
                body.len(), buf_recv, body);

            (buf_recv.into_inner(), body)
        })
    }).map_err(|(buf_recv, e)| (buf_recv.into_inner(), common::convert_read_io_error(e)))
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

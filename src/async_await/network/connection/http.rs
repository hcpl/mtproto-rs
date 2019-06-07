use std::fmt;
use std::marker::Unpin;
use std::str;

use error_chain::bail;
use futures_io::AsyncRead;
use futures_util::compat::{AsyncRead01CompatExt, Future01CompatExt};
use futures_util::io::{AsyncBufReadExt, AsyncReadExt, BufReader};
use futures_util::stream::StreamExt;
use log::{debug, error};
use tokio_tcp::TcpStream;

use crate::error::{self, ErrorKind};
use crate::async_await::network::connection::common;
use crate::tl::message::{RawMessageCommon, RawMessageSeedCommon};


#[derive(Debug)]
pub struct ConnectionHttp {
    socket: TcpStream,
}

#[async_transform::impl_async_methods_to_impl_futures]
impl ConnectionHttp {
    pub fn split(self) -> (SendConnectionHttp, RecvConnectionHttp) {
        let (recv_socket, send_socket) = self.socket.compat().split();

        (
            SendConnectionHttp { send_socket },
            RecvConnectionHttp { recv_socket },
        )
    }
}

generate_create_connection_methods_for!(ConnectionHttp,
    connection_log_str = "HTTP connection",
    ret = Self { socket }
);
generate_send_connection_methods_for!(ConnectionHttp);
generate_recv_connection_methods_for!(ConnectionHttp);
generate_request_connection_methods_for!(ConnectionHttp);

generate_send_raw_method_for!(ConnectionHttp,
    prepare_send_data = prepare_send_data(raw_message)?,
    perform_send = {
        let mut socket = {
            let socket_mut = &mut self.socket;
            let socket_mut03 = socket_mut.compat();
            socket_mut03
        };
        common::perform_send(&mut socket, &data).await
    }
);

generate_recv_raw_method_for!(ConnectionHttp,
    perform_recv = {
        let socket_mut = &mut self.socket;
        let mut socket_mut03 = socket_mut.compat();
        perform_recv(&mut socket_mut03).await?
    },
    parse_response = parse_response::<S>(&data)?
);

delegate_impl_connection_for!(ConnectionHttp with
    SendConnection = SendConnectionHttp,
    RecvConnection = RecvConnectionHttp);


#[derive(Debug)]
pub struct SendConnectionHttp {
    send_socket: futures_util::io::WriteHalf<futures_util::compat::Compat01As03<TcpStream>>,
}

generate_send_connection_methods_for!(SendConnectionHttp);
generate_send_raw_method_for!(SendConnectionHttp,
    prepare_send_data = prepare_send_data(raw_message)?,
    perform_send = common::perform_send(&mut self.send_socket, &data).await
);

delegate_impl_send_connection_for!(SendConnectionHttp);


#[derive(Debug)]
pub struct RecvConnectionHttp {
    recv_socket: futures_util::io::ReadHalf<futures_util::compat::Compat01As03<TcpStream>>,
}

generate_recv_connection_methods_for!(RecvConnectionHttp);
generate_recv_raw_method_for!(RecvConnectionHttp,
    perform_recv = perform_recv(&mut self.recv_socket).await?,
    parse_response = parse_response::<S>(&data)?
);

delegate_impl_recv_connection_for!(RecvConnectionHttp);


async fn perform_recv<R>(recv: &mut R) -> error::Result<Vec<u8>>
where
    R: fmt::Debug + AsyncRead + Unpin,
{
    let mut buf_recv = BufReader::new(recv);
    let mut lines = (&mut buf_recv).lines();
    debug!("Lines stream of buffered recv: {:?}", lines);

    let mut i = 0usize;
    let len = loop {
        i += 1;
        debug!("Loop iteration #{}: lines = {:?}", i, lines);

        match lines.next().await.transpose()? {
            Some(line) => {
                debug!("Polled line: line = {:?}, lines = {:?}", line, lines);

                if line.len() >= 16 && line[..16].eq_ignore_ascii_case("Content-Length: ") {
                    let len = line[16..].parse::<usize>().unwrap();
                    debug!("Content length: {}", len);
                    break len;
                }
            },
            None => panic!("HTTP response should not end here!"),  // FIXME
        }
    };

    match lines.next().await.transpose()? {
        Some(line) => assert_eq!(line, ""),
        None => panic!("HTTP response should not end here!"),  // FIXME
    }

    debug!("foo");

    let mut buf = vec![0; len];
    buf_recv.read_exact(&mut buf).await?;

    debug!("Received {} bytes from server: buffered recv = {:?}, bytes = {:?}", len, buf_recv, buf);

    Ok(buf)
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

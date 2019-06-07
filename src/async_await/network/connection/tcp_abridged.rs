use std::fmt;
use std::marker::Unpin;
use std::mem;

use byteorder::{ByteOrder, LittleEndian};
use error_chain::bail;
use futures_io::AsyncRead;
use futures_util::compat::{AsyncRead01CompatExt, Future01CompatExt};
use futures_util::io::AsyncReadExt;
use log::debug;
use tokio_tcp::TcpStream;

use crate::error::{self, ErrorKind};
use crate::async_await::network::connection::{common, tcp_common};
use crate::tl::message::RawMessageCommon;


#[derive(Debug)]
pub struct ConnectionTcpAbridged {
    socket: TcpStream,
    is_first_request: bool,
}

#[async_transform::impl_async_methods_to_impl_futures]
impl ConnectionTcpAbridged {
    pub fn split(self) -> (SendConnectionTcpAbridged, RecvConnectionTcpAbridged) {
        let Self { socket, is_first_request } = self;
        let (recv_socket, send_socket) = socket.compat().split();

        (
            SendConnectionTcpAbridged { send_socket, is_first_request },
            RecvConnectionTcpAbridged { recv_socket },
        )
    }
}

generate_create_connection_methods_for!(ConnectionTcpAbridged,
    connection_log_str = "TCP connection in abridged mode",
    ret = Self { socket, is_first_request: true }
);
generate_send_connection_methods_for!(ConnectionTcpAbridged);
generate_recv_connection_methods_for!(ConnectionTcpAbridged);
generate_request_connection_methods_for!(ConnectionTcpAbridged);

generate_send_raw_method_for!(ConnectionTcpAbridged,
    prepare_send_data = prepare_send_data(raw_message, &mut self.is_first_request)?,
    perform_send = {
        let mut socket = {
            let socket_mut = &mut self.socket;
            let socket_mut03 = socket_mut.compat();
            socket_mut03
        };
        common::perform_send(&mut socket, &data).await
    }
);

generate_recv_raw_method_for!(ConnectionTcpAbridged,
    perform_recv = {
        let socket_mut = &mut self.socket;
        let mut socket_mut03 = socket_mut.compat();
        perform_recv(&mut socket_mut03).await?
    },
    parse_response = tcp_common::parse_response::<S>(&data)?
);

delegate_impl_connection_for!(ConnectionTcpAbridged with
    SendConnection = SendConnectionTcpAbridged,
    RecvConnection = RecvConnectionTcpAbridged);


#[derive(Debug)]
pub struct SendConnectionTcpAbridged {
    send_socket: futures_util::io::WriteHalf<futures_util::compat::Compat01As03<TcpStream>>,
    is_first_request: bool,
}

generate_send_connection_methods_for!(SendConnectionTcpAbridged);
generate_send_raw_method_for!(SendConnectionTcpAbridged,
    prepare_send_data = prepare_send_data(raw_message, &mut self.is_first_request)?,
    perform_send = common::perform_send(&mut self.send_socket, &data).await
);

delegate_impl_send_connection_for!(SendConnectionTcpAbridged);


#[derive(Debug)]
pub struct RecvConnectionTcpAbridged {
    recv_socket: futures_util::io::ReadHalf<futures_util::compat::Compat01As03<TcpStream>>,
}

generate_recv_connection_methods_for!(RecvConnectionTcpAbridged);
generate_recv_raw_method_for!(RecvConnectionTcpAbridged,
    perform_recv = perform_recv(&mut self.recv_socket).await?,
    parse_response = tcp_common::parse_response::<S>(&data)?
);

delegate_impl_recv_connection_for!(RecvConnectionTcpAbridged);


async fn perform_recv<R>(recv: &mut R) -> error::Result<Vec<u8>>
where
    R: fmt::Debug + AsyncRead + Unpin,
{
    let mut byte_id = [0; 1];
    recv.read_exact(&mut byte_id).await?;

    debug!("Received {} bytes from server: recv = {:?}, bytes = {:?}",
        byte_id.len(), recv, byte_id);

    let len = if byte_id == [0x7f] {
        let mut bytes_len = [0; 3];
        recv.read_exact(&mut bytes_len).await?;

        debug!("Received {} bytes from server: recv = {:?}, bytes = {:?}",
            bytes_len.len(), recv, bytes_len);

        LittleEndian::read_uint(&bytes_len, 3) as usize * 4
    } else {
        byte_id[0] as usize * 4
    };

    debug!("Got length from server: recv = {:?}, length = {}", recv, len);

    let mut body = vec![0; len];
    recv.read_exact(&mut body).await?;

    Ok(body)
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

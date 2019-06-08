use std::fmt;
use std::mem;

use byteorder::{ByteOrder, LittleEndian};
use error_chain::bail;
use futures::Future;
use futures::future::Either;
use log::debug;
use tokio_io::AsyncRead;
use tokio_tcp::TcpStream;

use crate::async_io;
use crate::error::{self, ErrorKind};
use crate::network::connection::{common, tcp_common};
use crate::tl::message::RawMessageCommon;


#[derive(Debug)]
pub struct ConnectionTcpAbridged {
    socket: TcpStream,
    is_first_request: bool,
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

    generate_create_connection_methods!(
        connection_log_str = "TCP connection in intermediate mode",
        ret = |socket| Self { socket, is_first_request: true },
    );

    generate_send_connection_methods!();
    generate_send_raw_method!(
        prepare_send_data = |raw_message, self_: &mut Self| prepare_send_data(raw_message, &mut self_.is_first_request),
        perform_send = |socket, data| common::perform_send(socket, data),
        self_to_fields = |self_: Self| (self_.socket, self_.is_first_request),
        self_from_fields = |socket, is_first_request| Self { socket, is_first_request },
    );

    generate_recv_connection_methods!();
    generate_recv_raw_method!(
        parse_response = |data| tcp_common::parse_response::<S>(data),
        self_to_fields = |self_: Self| (self_.socket, self_.is_first_request),
        self_from_fields = |socket, is_first_request| Self { socket, is_first_request },
    );

    generate_request_connection_methods!();
}

delegate_impl_connection_for!(ConnectionTcpAbridged with
    SendConnection = SendConnectionTcpAbridged,
    RecvConnection = RecvConnectionTcpAbridged);


#[derive(Debug)]
pub struct SendConnectionTcpAbridged {
    send_socket: tokio_io::io::WriteHalf<TcpStream>,
    is_first_request: bool,
}

impl SendConnectionTcpAbridged {
    generate_send_connection_methods!();
    generate_send_raw_method!(
        prepare_send_data = |raw_message, self_: &mut Self| prepare_send_data(raw_message, &mut self_.is_first_request),
        perform_send = |send_socket, data| common::perform_send(send_socket, data),
        self_to_fields = |self_: Self| (self_.send_socket, self_.is_first_request),
        self_from_fields = |send_socket, is_first_request| Self { send_socket, is_first_request },
    );
}

delegate_impl_send_connection_for!(SendConnectionTcpAbridged);


#[derive(Debug)]
pub struct RecvConnectionTcpAbridged {
    recv_socket: tokio_io::io::ReadHalf<TcpStream>,
}

impl RecvConnectionTcpAbridged {
    generate_recv_connection_methods!();
    generate_recv_raw_method!(
        parse_response = |data| tcp_common::parse_response::<S>(data),
        self_to_fields = |self_: Self| (self_.recv_socket, ()),
        self_from_fields = |recv_socket, ()| Self { recv_socket },
    );
}

delegate_impl_recv_connection_for!(RecvConnectionTcpAbridged);


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

use std::fmt;
use std::mem;

use byteorder::{ByteOrder, LittleEndian};
use error_chain::bail;
use futures::Future;
use log::debug;
use tokio_io::AsyncRead;
use tokio_tcp::TcpStream;

use crate::async_io;
use crate::error::{self, ErrorKind};
use crate::network::connection::{common, tcp_common};
use crate::tl::message::RawMessageCommon;
use crate::utils::safe_uint_cast;


#[derive(Debug)]
pub struct ConnectionTcpIntermediate {
    socket: TcpStream,
    is_first_request: bool,
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

delegate_impl_connection_for!(ConnectionTcpIntermediate with
    SendConnection = SendConnectionTcpIntermediate,
    RecvConnection = RecvConnectionTcpIntermediate);


#[derive(Debug)]
pub struct SendConnectionTcpIntermediate {
    send_socket: tokio_io::io::WriteHalf<TcpStream>,
    is_first_request: bool,
}

impl SendConnectionTcpIntermediate {
    generate_send_connection_methods!();
    generate_send_raw_method!(
        prepare_send_data = |raw_message, self_: &mut Self| prepare_send_data(raw_message, &mut self_.is_first_request),
        perform_send = |send_socket, data| common::perform_send(send_socket, data),
        self_to_fields = |self_: Self| (self_.send_socket, self_.is_first_request),
        self_from_fields = |send_socket, is_first_request| Self { send_socket, is_first_request },
    );
}

delegate_impl_send_connection_for!(SendConnectionTcpIntermediate);


#[derive(Debug)]
pub struct RecvConnectionTcpIntermediate {
    recv_socket: tokio_io::io::ReadHalf<TcpStream>,
}

impl RecvConnectionTcpIntermediate {
    generate_recv_connection_methods!();
    generate_recv_raw_method!(
        parse_response = |data| tcp_common::parse_response::<S>(data),
        self_to_fields = |self_: Self| (self_.recv_socket, ()),
        self_from_fields = |recv_socket, ()| Self { recv_socket },
    );
}

delegate_impl_recv_connection_for!(RecvConnectionTcpIntermediate);


fn perform_recv<R>(recv: R)
    -> impl Future<Item = (R, Vec<u8>), Error = (R, error::Error)>
where
    R: fmt::Debug + AsyncRead,
{
    async_io::read_exact(recv, [0; 4]).and_then(|(recv, bytes_len)| {
        debug!("Received {} bytes from server: recv = {:?}, bytes = {:?}",
            bytes_len.len(), recv, bytes_len);

        let len = LittleEndian::read_u32(&bytes_len);
        async_io::read_exact(recv, vec![0; len as usize]) // FIXME: use safe cast
    }).map_err(|(recv, e)| (recv, common::convert_read_io_error(e)))
}

fn prepare_send_data<R>(raw_message: &R, is_first_request: &mut bool) -> error::Result<Vec<u8>>
where
    R: RawMessageCommon,
{
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
            serde_mtproto::to_writer(message_bytes, raw_message)?;
        }

        Ok(buf)
    } else {
        bail!(ErrorKind::MessageTooLong(data_size));
    }
}

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
use crate::utils::safe_uint_cast;


#[derive(Debug)]
pub struct ConnectionTcpIntermediate {
    socket: TcpStream,
    is_first_request: bool,
}

#[async_transform::impl_async_methods_to_impl_futures]
impl ConnectionTcpIntermediate {
    pub fn split(self) -> (SendConnectionTcpIntermediate, RecvConnectionTcpIntermediate) {
        let Self { socket, is_first_request } = self;
        let (recv_socket, send_socket) = socket.compat().split();

        (
            SendConnectionTcpIntermediate { send_socket, is_first_request },
            RecvConnectionTcpIntermediate { recv_socket },
        )
    }
}

generate_create_connection_methods_for!(ConnectionTcpIntermediate,
    connection_log_str = "TCP connection in intermediate mode",
    ret = Self { socket, is_first_request: true }
);
generate_send_connection_methods_for!(ConnectionTcpIntermediate);
generate_recv_connection_methods_for!(ConnectionTcpIntermediate);
generate_request_connection_methods_for!(ConnectionTcpIntermediate);

generate_send_raw_method_for!(ConnectionTcpIntermediate,
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

generate_recv_raw_method_for!(ConnectionTcpIntermediate,
    perform_recv = {
        let socket_mut = &mut self.socket;
        let mut socket_mut03 = socket_mut.compat();
        perform_recv(&mut socket_mut03).await?
    },
    parse_response = tcp_common::parse_response::<S>(&data)?
);

delegate_impl_connection_for!(ConnectionTcpIntermediate with
    SendConnection = SendConnectionTcpIntermediate,
    RecvConnection = RecvConnectionTcpIntermediate);


#[derive(Debug)]
pub struct SendConnectionTcpIntermediate {
    send_socket: futures_util::io::WriteHalf<futures_util::compat::Compat01As03<TcpStream>>,
    is_first_request: bool,
}

generate_send_connection_methods_for!(SendConnectionTcpIntermediate);
generate_send_raw_method_for!(SendConnectionTcpIntermediate,
    prepare_send_data = prepare_send_data(raw_message, &mut self.is_first_request)?,
    perform_send = common::perform_send(&mut self.send_socket, &data).await
);

delegate_impl_send_connection_for!(SendConnectionTcpIntermediate);


#[derive(Debug)]
pub struct RecvConnectionTcpIntermediate {
    recv_socket: futures_util::io::ReadHalf<futures_util::compat::Compat01As03<TcpStream>>,
}

generate_recv_connection_methods_for!(RecvConnectionTcpIntermediate);
generate_recv_raw_method_for!(RecvConnectionTcpIntermediate,
    perform_recv = perform_recv(&mut self.recv_socket).await?,
    parse_response = tcp_common::parse_response::<S>(&data)?
);

delegate_impl_recv_connection_for!(RecvConnectionTcpIntermediate);


async fn perform_recv<R>(recv: &mut R) -> error::Result<Vec<u8>>
where
    R: fmt::Debug + AsyncRead + Unpin,
{
    let mut bytes_len = [0; 4];
    recv.read_exact(&mut bytes_len).await?;

    debug!("Received {} bytes from server: recv = {:?}, bytes = {:?}",
        bytes_len.len(), recv, bytes_len);

    let len = LittleEndian::read_u32(&bytes_len);

    let mut body = vec![0; len as usize]; // FIXME: use safe cast
    recv.read_exact(&mut body).await?;

    Ok(body)
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

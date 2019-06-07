use std::fmt;
use std::marker::Unpin;
use std::mem;

use byteorder::{ByteOrder, LittleEndian};
use crc::crc32;
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
pub struct ConnectionTcpFull {
    socket: TcpStream,
    sent_counter: u32,
}

#[async_transform::impl_async_methods_to_impl_futures]
impl ConnectionTcpFull {
    pub fn split(self) -> (SendConnectionTcpFull, RecvConnectionTcpFull) {
        let Self { socket, sent_counter } = self;
        let (recv_socket, send_socket) = socket.compat().split();

        (
            SendConnectionTcpFull { send_socket, sent_counter },
            RecvConnectionTcpFull { recv_socket },
        )
    }
}

generate_create_connection_methods_for!(ConnectionTcpFull,
    connection_log_str = "TCP connection in full mode",
    ret = Self { socket, sent_counter: 0 }
);
generate_send_connection_methods_for!(ConnectionTcpFull);
generate_recv_connection_methods_for!(ConnectionTcpFull);
generate_request_connection_methods_for!(ConnectionTcpFull);

generate_send_raw_method_for!(ConnectionTcpFull,
    prepare_send_data = prepare_send_data(raw_message, &mut self.sent_counter)?,
    perform_send = {
        let mut socket = {
            let socket_mut = &mut self.socket;
            let socket_mut03 = socket_mut.compat();
            socket_mut03
        };
        common::perform_send(&mut socket, &data).await
    }
);

generate_recv_raw_method_for!(ConnectionTcpFull,
    perform_recv = {
        let socket_mut = &mut self.socket;
        let mut socket_mut03 = socket_mut.compat();
        perform_recv(&mut socket_mut03).await?
    },
    parse_response = tcp_common::parse_response::<S>(&data)?
);

delegate_impl_connection_for!(ConnectionTcpFull with
    SendConnection = SendConnectionTcpFull,
    RecvConnection = RecvConnectionTcpFull);


#[derive(Debug)]
pub struct SendConnectionTcpFull {
    send_socket: futures_util::io::WriteHalf<futures_util::compat::Compat01As03<TcpStream>>,
    sent_counter: u32,
}

generate_send_connection_methods_for!(SendConnectionTcpFull);
generate_send_raw_method_for!(SendConnectionTcpFull,
    prepare_send_data = prepare_send_data(raw_message, &mut self.sent_counter)?,
    perform_send = common::perform_send(&mut self.send_socket, &data).await
);

delegate_impl_send_connection_for!(SendConnectionTcpFull);


#[derive(Debug)]
pub struct RecvConnectionTcpFull {
    recv_socket: futures_util::io::ReadHalf<futures_util::compat::Compat01As03<TcpStream>>,
}

generate_recv_connection_methods_for!(RecvConnectionTcpFull);
generate_recv_raw_method_for!(RecvConnectionTcpFull,
    perform_recv = perform_recv(&mut self.recv_socket).await?,
    parse_response = tcp_common::parse_response::<S>(&data)?
);

delegate_impl_recv_connection_for!(RecvConnectionTcpFull);


async fn perform_recv<R>(recv: &mut R) -> error::Result<Vec<u8>>
where
    R: fmt::Debug + AsyncRead + Unpin,
{
    let mut first_bytes = [0; 8];
    recv.read_exact(&mut first_bytes).await?;

    debug!("Received {} bytes from server: recv = {:?}, bytes = {:?}",
        first_bytes.len(), recv, first_bytes);

    let len = LittleEndian::read_u32(&first_bytes[0..4]);
    let ulen = len as usize;  // FIXME: use safe cast here
    // TODO: check seq_no
    let _seq_no = LittleEndian::read_u32(&first_bytes[4..8]);

    let mut last_bytes = vec![0; ulen - 8];
    recv.read_exact(&mut last_bytes).await?;

    debug!("Received {} bytes from server: recv = {:?}, bytes = {:?}",
        last_bytes.len(), recv, last_bytes);

    let checksum = LittleEndian::read_u32(&last_bytes[ulen - 12..ulen - 8]);
    let mut body = last_bytes;
    body.truncate(ulen - 12);

    let mut value = 0;
    value = crc32::update(value, &crc32::IEEE_TABLE, &first_bytes[0..4]);
    value = crc32::update(value, &crc32::IEEE_TABLE, &first_bytes[4..8]);
    value = crc32::update(value, &crc32::IEEE_TABLE, &body);

    if value == checksum {
        Ok(body)
    } else {
        bail!(ErrorKind::TcpFullModeResponseInvalidChecksum(value, checksum));
    }
}

fn prepare_send_data<R>(raw_message: &R, sent_counter: &mut u32) -> error::Result<Vec<u8>>
where
    R: RawMessageCommon,
{
    const SIZE_SIZE: usize = mem::size_of::<u32>();
    const SENT_COUNTER_SIZE: usize = mem::size_of::<u32>();
    let raw_message_size = raw_message.size_hint()?;
    const CRC_SIZE: usize = mem::size_of::<u32>();

    // FIXME: May overflow on 32-bit systems
    let data_size = SIZE_SIZE + SENT_COUNTER_SIZE + raw_message_size + CRC_SIZE;

    if let Ok(data_size_u32) = safe_uint_cast::<usize, u32>(data_size) {
        let mut buf = vec![0; data_size];

        {
            let (size_bytes, rest) = buf.split_at_mut(SIZE_SIZE);
            let (sent_counter_bytes, rest2) = rest.split_at_mut(SENT_COUNTER_SIZE);
            let (message_bytes, _) = rest2.split_at_mut(raw_message_size);

            LittleEndian::write_u32(size_bytes, data_size_u32);
            LittleEndian::write_u32(sent_counter_bytes, *sent_counter);
            serde_mtproto::to_writer(message_bytes, raw_message)?;
        }

        {
            let (non_crc_bytes, crc_bytes) = buf.split_at_mut(data_size - CRC_SIZE);

            let crc = crc32::checksum_ieee(&*non_crc_bytes);
            LittleEndian::write_u32(crc_bytes, crc);
        }

        *sent_counter += 1;

        Ok(buf)
    } else {
        bail!(ErrorKind::MessageTooLong(data_size));
    }
}

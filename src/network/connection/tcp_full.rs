use std::fmt;
use std::mem;

use byteorder::{ByteOrder, LittleEndian};
use crc::crc32;
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
pub struct ConnectionTcpFull {
    socket: TcpStream,
    sent_counter: u32,
}

impl ConnectionTcpFull {
    pub fn split(self) -> (SendConnectionTcpFull, RecvConnectionTcpFull) {
        let Self { socket, sent_counter } = self;
        let (recv_socket, send_socket) = socket.split();

        (
            SendConnectionTcpFull { send_socket, sent_counter },
            RecvConnectionTcpFull { recv_socket },
        )
    }

    generate_create_connection_methods!(
        connection_log_str = "TCP connection in full mode",
        ret = |socket| Self { socket, sent_counter: 0 },
    );

    generate_send_connection_methods!();
    generate_send_raw_method!(
        prepare_send_data = |raw_message, self_: &mut Self| prepare_send_data(raw_message, &mut self_.sent_counter),
        perform_send = |socket, data| common::perform_send(socket, data),
        self_to_fields = |self_: Self| (self_.socket, self_.sent_counter),
        self_from_fields = |socket, sent_counter| Self { socket, sent_counter },
    );

    generate_recv_connection_methods!();
    generate_recv_raw_method!(
        parse_response = |data| tcp_common::parse_response::<S>(data),
        self_to_fields = |self_: Self| (self_.socket, self_.sent_counter),
        self_from_fields = |socket, sent_counter| Self { socket, sent_counter },
    );

    generate_request_connection_methods!();
}

delegate_impl_connection_for!(ConnectionTcpFull with
    SendConnection = SendConnectionTcpFull,
    RecvConnection = RecvConnectionTcpFull);


#[derive(Debug)]
pub struct SendConnectionTcpFull {
    send_socket: tokio_io::io::WriteHalf<TcpStream>,
    sent_counter: u32,
}

impl SendConnectionTcpFull {
    generate_send_connection_methods!();
    generate_send_raw_method!(
        prepare_send_data = |raw_message, self_: &mut Self| prepare_send_data(raw_message, &mut self_.sent_counter),
        perform_send = |send_socket, data| common::perform_send(send_socket, data),
        self_to_fields = |self_: Self| (self_.send_socket, self_.sent_counter),
        self_from_fields = |send_socket, sent_counter| Self { send_socket, sent_counter },
    );
}

delegate_impl_send_connection_for!(SendConnectionTcpFull);


#[derive(Debug)]
pub struct RecvConnectionTcpFull {
    recv_socket: tokio_io::io::ReadHalf<TcpStream>,
}

impl RecvConnectionTcpFull {
    generate_recv_connection_methods!();
    generate_recv_raw_method!(
        parse_response = |data| tcp_common::parse_response::<S>(data),
        self_to_fields = |self_: Self| (self_.recv_socket, ()),
        self_from_fields = |recv_socket, ()| Self { recv_socket },
    );
}

delegate_impl_recv_connection_for!(RecvConnectionTcpFull);


fn perform_recv<R>(recv: R)
    -> impl Future<Item = (R, Vec<u8>), Error = (R, error::Error)>
where
    R: fmt::Debug + AsyncRead,
{
    async_io::read_exact(recv, [0; 8]).map_err(|(recv, e)| {
        (recv, e.into())
    }).and_then(|(recv, first_bytes)| {
        debug!("Received {} bytes from server: recv = {:?}, bytes = {:?}",
            first_bytes.len(), recv, first_bytes);

        let len = LittleEndian::read_u32(&first_bytes[0..4]);
        let ulen = len as usize;  // FIXME: use safe cast here
        // TODO: check seq_no
        let _seq_no = LittleEndian::read_u32(&first_bytes[4..8]);

        async_io::read_exact(recv, vec![0; ulen - 8])
            .map_err(|(recv, e)| (recv, common::convert_read_io_error(e)))
            .and_then(move |(recv, last_bytes)| {
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
                    Ok((recv, body))
                } else {
                    bail!((recv,
                        ErrorKind::TcpFullModeResponseInvalidChecksum(value, checksum).into()))
                }
            })
    })
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

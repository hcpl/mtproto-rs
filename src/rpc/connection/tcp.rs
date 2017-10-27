use std::io;
use std::net::SocketAddr;

use byteorder::{ByteOrder, LittleEndian};
use crc::crc32;
use futures::{self, Future};
use log::LogLevel;
use tokio_core::net::TcpStream;
use tokio_io;

use error::{self, ErrorKind};

use super::TCP_SERVER_ADDRS;


#[derive(Debug)]
pub struct TcpConnection {
    mode_info: TcpModeInfo,
    server_addr: SocketAddr,
}

impl Default for TcpConnection {
    fn default() -> TcpConnection {
        TcpConnection::new(TcpMode::Full, TCP_SERVER_ADDRS[0])
    }
}

impl TcpConnection {
    pub fn new(mode: TcpMode, server_addr: SocketAddr) -> TcpConnection {
        if log_enabled!(LogLevel::Info) {
            let mode_str = match mode {
                TcpMode::Full => "full",
                TcpMode::Intermediate => "intermediate",
                TcpMode::Abridged => "abridged",
            };

            info!("New TCP connection in {} mode to {}", mode_str, server_addr);
        }

        TcpConnection { mode_info: TcpModeInfo::from(mode), server_addr }
    }

    pub fn request(&mut self, socket: TcpStream, serialized_message: Vec<u8>)
        -> Box<Future<Item = (TcpStream, Vec<u8>), Error = error::Error>>
    {
        let mode_info: &mut MtProtoTcpMode = match self.mode_info {
            TcpModeInfo::Full(ref mut mode_info) => mode_info,
            TcpModeInfo::Intermediate(ref mut mode_info) => mode_info,
            TcpModeInfo::Abridged(ref mut mode_info) => mode_info,
        };

        mode_info.request(socket, serialized_message)
    }
}


#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TcpMode {
    Full,
    Intermediate,
    Abridged,
}

#[derive(Debug)]
enum TcpModeInfo {
    Full(FullModeInfo),
    Intermediate(IntermediateModeInfo),
    Abridged(AbridgedModeInfo),
}

impl From<TcpMode> for TcpModeInfo {
    fn from(mode: TcpMode) -> TcpModeInfo {
        match mode {
            TcpMode::Full         => TcpModeInfo::Full(FullModeInfo::new()),
            TcpMode::Intermediate => TcpModeInfo::Intermediate(IntermediateModeInfo::new()),
            TcpMode::Abridged     => TcpModeInfo::Abridged(AbridgedModeInfo::new()),
        }
    }
}


macro_rules! bailf {
    ($e:expr) => {
        return Box::new(futures::future::err($e.into()))
    }
}


trait MtProtoTcpMode {
    fn request(&mut self, socket: TcpStream, serialized_message: Vec<u8>)
        -> Box<Future<Item = (TcpStream, Vec<u8>), Error = error::Error>>;
}


#[derive(Debug)]
struct FullModeInfo {
    sent_counter: u32,
}

impl FullModeInfo {
    fn new() -> FullModeInfo {
        FullModeInfo { sent_counter: 0 }
    }
}

impl MtProtoTcpMode for FullModeInfo {
    fn request(&mut self, socket: TcpStream, serialized_message: Vec<u8>)
        -> Box<Future<Item = (TcpStream, Vec<u8>), Error = error::Error>>
    {
        let len = serialized_message.len() + 12;
        let data = if len <= 0xff_ff_ff_ff {
            let mut data = vec![0; len];

            LittleEndian::write_u32(&mut data[0..4], len as u32);  // cast is safe here
            LittleEndian::write_u32(&mut data[4..8], self.sent_counter);
            data[8..len-4].copy_from_slice(&serialized_message);

            let crc = crc32::checksum_ieee(&data[0..len-4]);
            self.sent_counter += 1;

            LittleEndian::write_u32(&mut data[len-4..], crc);

            data
        } else {
            bailf!(ErrorKind::MessageTooLong(len));
        };

        let request = tokio_io::io::write_all(socket, data);

        let response = request.and_then(|(socket, _request_bytes)| {
            tokio_io::io::read_exact(socket, [0; 8])
        }).and_then(|(socket, first_bytes)| {
            let len = LittleEndian::read_u32(&first_bytes[0..4]);
            let ulen = len as usize;  // FIXME: use safe cast here
            // TODO: check seq_no
            let _seq_no = LittleEndian::read_u32(&first_bytes[4..8]);

            tokio_io::io::read_exact(socket, vec![0; ulen - 8]).and_then(move |(socket, last_bytes)| {
                let checksum = LittleEndian::read_u32(&last_bytes[ulen - 12..ulen - 8]);
                let mut body = last_bytes;
                body.truncate(ulen - 12);

                let mut value = 0;
                value = crc32::update(value, &crc32::IEEE_TABLE, &first_bytes[0..4]);
                value = crc32::update(value, &crc32::IEEE_TABLE, &first_bytes[4..8]);
                value = crc32::update(value, &crc32::IEEE_TABLE, &body);

                if value == checksum {
                    futures::future::ok((socket, body))
                } else {
                    futures::future::err(io::Error::new(io::ErrorKind::Other, "invalid checksum"))
                }
            })
        });

        Box::new(response.map_err(Into::into))
    }
}


#[derive(Debug)]
struct IntermediateModeInfo {
    is_first_request: bool,
}

impl IntermediateModeInfo {
    fn new() -> IntermediateModeInfo {
        IntermediateModeInfo { is_first_request: true }
    }
}

impl MtProtoTcpMode for IntermediateModeInfo {
    fn request(&mut self, socket: TcpStream, serialized_message: Vec<u8>)
        -> Box<Future<Item = (TcpStream, Vec<u8>), Error = error::Error>>
    {
        let len = serialized_message.len();
        let data = if len <= 0xff_ff_ff_ff {
            let mut data = vec![0; 4 + len];

            LittleEndian::write_u32(&mut data[0..4], len as u32);
            data[4..].copy_from_slice(&serialized_message);

            data
        } else {
            bailf!(ErrorKind::MessageTooLong(len));
        };

        let init: Box<Future<Item = (TcpStream, &'static [u8]), Error = io::Error>> = if self.is_first_request {
            self.is_first_request = false;
            Box::new(tokio_io::io::write_all(socket, b"\xee\xee\xee\xee".as_ref()))
        } else {
            Box::new(futures::future::ok((socket, [].as_ref())))
        };

        let request = init.and_then(|(socket, _init_bytes)| {
            tokio_io::io::write_all(socket, data)
        });

        let response = request.and_then(|(socket, _request_bytes)| {
            tokio_io::io::read_exact(socket, [0; 4])
        }).and_then(|(socket, bytes_len)| {
            let len = LittleEndian::read_u32(&bytes_len);
            tokio_io::io::read_exact(socket, vec![0; len as usize]) // FIXME: use safe cast
        });

        Box::new(response.map_err(Into::into))
    }
}


#[derive(Debug)]
struct AbridgedModeInfo {
    is_first_request: bool,
}

impl AbridgedModeInfo {
    fn new() -> AbridgedModeInfo {
        AbridgedModeInfo { is_first_request: true }
    }
}

impl MtProtoTcpMode for AbridgedModeInfo {
    fn request(&mut self, socket: TcpStream, serialized_message: Vec<u8>)
        -> Box<Future<Item = (TcpStream, Vec<u8>), Error = error::Error>>
    {
        let mut data = if self.is_first_request {
            self.is_first_request = false;
            vec![0xef]
        } else {
            vec![]
        };

        let len = serialized_message.len() / 4;
        if len < 0x7f {
            data.push(len as u8);
        } else if len < 0xff_ff_ff {
            data.push(0x7f);
            LittleEndian::write_uint(&mut data, len as u64, 3); // FIXME: use safe cast here
        } else {
            bailf!(ErrorKind::MessageTooLong(len));
        }

        data.extend(serialized_message);
        let request = tokio_io::io::write_all(socket, data);

        let response = request.and_then(|(socket, _request_bytes)| {
            tokio_io::io::read_exact(socket, [0; 1])
        }).and_then(|(socket, byte_id)| {
            let boxed: Box<Future<Item = (TcpStream, usize), Error = io::Error>> = if byte_id == [0x7f] {
                Box::new(tokio_io::io::read_exact(socket, [0; 3]).map(|(socket, bytes_len)| {
                    let len = LittleEndian::read_uint(&bytes_len, 3) as usize * 4;
                    (socket, len)
                }))
            } else {
                Box::new(futures::future::ok((socket, byte_id[0] as usize * 4)))
            };

            boxed
        }).and_then(|(socket, len)| {
            tokio_io::io::read_exact(socket, vec![0; len])
        });

        Box::new(response.map_err(Into::into))
    }
}

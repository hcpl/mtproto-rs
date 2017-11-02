use std::fmt;
use std::io;
use std::net::SocketAddr;

use byteorder::{ByteOrder, LittleEndian};
use crc::crc32;
use futures::{self, Future, IntoFuture};
use log::LogLevel;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_mtproto::{self, MtProtoSized};
use tokio_core::net::TcpStream;
use tokio_io;

use tl::TLObject;
use error::{self, ErrorKind};
use rpc::{Message, MessageType, Session};

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

    pub fn request<T, U>(&mut self,
                         socket: TcpStream,
                         session: Session,
                         request_message: Message<T>,
                         response_message_type: MessageType)
        -> Box<Future<Item = (TcpStream, Message<U>, Session), Error = error::Error>>
        where T: fmt::Debug + Serialize + TLObject,
              U: fmt::Debug + DeserializeOwned + TLObject,
    {
        let request_future = match self.mode_info {
            TcpModeInfo::Full(ref mut mode_info)         => mode_info.request(socket, request_message),
            TcpModeInfo::Intermediate(ref mut mode_info) => mode_info.request(socket, request_message),
            TcpModeInfo::Abridged(ref mut mode_info)     => mode_info.request(socket, request_message),
        };

        Box::new(request_future.and_then(move |(socket, response_bytes)| {
            parse_response::<U>(&session, &response_bytes, response_message_type)
                .into_future()
                .map(move |msg| (socket, msg, session))
        }))
    }
}

fn parse_response<T>(session: &Session,
                     response_bytes: &[u8],
                     message_type: MessageType)
                    -> error::Result<Message<T>>
    where T: fmt::Debug + DeserializeOwned
{
    debug!("Response bytes: {:?}", response_bytes);

    let len = response_bytes.len();

    if len == 4 { // Must be an error code
        // Error codes are represented as negative i32
        let code = LittleEndian::read_i32(response_bytes);
        bail!(ErrorKind::ErrorCode(-code));
    } else if len < 24 {
        bail!(ErrorKind::BadMessage(len));
    }

    let encrypted_data_len = match message_type {
        MessageType::PlainText => None,
        MessageType::Encrypted => Some((len - 24) as u32),
    };

    let response = session.process_message(&response_bytes, encrypted_data_len)?;
    debug!("Message received: {:#?}", &response);

    Ok(response)
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

macro_rules! tryf {
    ($e:expr) => {
        match { $e } {
            Ok(v) => v,
            Err(e) => bailf!(e),
        }
    }
}


trait MtProtoTcpMode {
    fn request<T>(&mut self, socket: TcpStream, message: Message<T>)
        -> Box<Future<Item = (TcpStream, Vec<u8>), Error = error::Error>>
        where T: fmt::Debug + Serialize + TLObject;
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
    fn request<T>(&mut self, socket: TcpStream, message: Message<T>)
        -> Box<Future<Item = (TcpStream, Vec<u8>), Error = error::Error>>
        where T: fmt::Debug + Serialize + TLObject
    {
        let size = tryf!(message.size_hint()) + 12;  // FIXME: Can overflow on 32-bit systems
        let data = if size <= 0xff_ff_ff_ff {
            let mut buf = vec![0; size];

            LittleEndian::write_u32(&mut buf[0..4], size as u32);  // cast is safe here
            LittleEndian::write_u32(&mut buf[4..8], self.sent_counter);
            tryf!(serde_mtproto::to_writer(&mut buf[8..size-4], &message));

            let crc = crc32::checksum_ieee(&buf[0..size-4]);
            LittleEndian::write_u32(&mut buf[size-4..], crc);

            self.sent_counter += 1;

            buf
        } else {
            bailf!(ErrorKind::MessageTooLong(size));
        };

        let request = tokio_io::io::write_all(socket, data);

        let response = request.and_then(|(socket, _request_bytes)| {
            tokio_io::io::read_exact(socket, [0; 8])
        }).then(|result|
            -> Box<Future<Item = (TcpStream, Vec<u8>), Error = error::Error>>
        {
            let (socket, first_bytes) = tryf!(result);

            let len = LittleEndian::read_u32(&first_bytes[0..4]);
            let ulen = len as usize;  // FIXME: use safe cast here
            // TODO: check seq_no
            let _seq_no = LittleEndian::read_u32(&first_bytes[4..8]);

            //tokio_io::io::read_exact(socket, vec![0; ulen - 8]).and_then(move |(socket, last_bytes)| {
            let process_last_bytes_future = tokio_io::io::read_exact(socket, vec![0; ulen - 8])
                .map_err(Into::into)
                .and_then(move |(socket, last_bytes)|
            {
                let checksum = LittleEndian::read_u32(&last_bytes[ulen - 12..ulen - 8]);
                let mut body = last_bytes;
                body.truncate(ulen - 12);

                let mut value = 0;
                value = crc32::update(value, &crc32::IEEE_TABLE, &first_bytes[0..4]);
                value = crc32::update(value, &crc32::IEEE_TABLE, &first_bytes[4..8]);
                value = crc32::update(value, &crc32::IEEE_TABLE, &body);

                let result_future = if value == checksum {
                    futures::future::ok((socket, body))
                } else {
                    futures::future::err(
                        //ErrorKind::TcpFullModeResponseInvalidChecksum(value, checksum).into())
                        error::Error::from(ErrorKind::TcpFullModeResponseInvalidChecksum(value, checksum)))
                };

                result_future
            });

            Box::new(process_last_bytes_future)
        });

        Box::new(response)
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
    fn request<T>(&mut self, socket: TcpStream, message: Message<T>)
        -> Box<Future<Item = (TcpStream, Vec<u8>), Error = error::Error>>
        where T: fmt::Debug + Serialize + TLObject
    {
        let size = tryf!(message.size_hint());
        let data = if size <= 0xff_ff_ff_ff {
            let mut buf = vec![0; 4 + size];

            LittleEndian::write_u32(&mut buf[0..4], size as u32);  // cast is safe here
            tryf!(serde_mtproto::to_writer(&mut buf[4..], &message));

            buf
        } else {
            bailf!(ErrorKind::MessageTooLong(size));
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
    fn request<T>(&mut self, socket: TcpStream, message: Message<T>)
        -> Box<Future<Item = (TcpStream, Vec<u8>), Error = error::Error>>
        where T: fmt::Debug + Serialize + TLObject
    {
        let size_div_4 = tryf!(message.size_hint()) / 4;  // div 4 required for abridged mode
        if size_div_4 > 0xff_ff_ff {
            bailf!(ErrorKind::MessageTooLong(size_div_4 * 4));
        }

        let data = {
            // For overall efficiency we trade code conciseness for reduced amount of dynamic
            // allocations since computation redundancy here will likely cost less than overhead of
            // consecutive allocations.
            let first_request_offset = if self.is_first_request { 1 } else { 0 };
            let msg_offset = first_request_offset + if size_div_4 < 0x7f { 1 } else { 4 };

            let mut buf = vec![0; msg_offset + size_div_4 * 4];

            if self.is_first_request {
                buf[0] = 0xef;
                self.is_first_request = false;
            }

            if size_div_4 < 0x7f {
                buf[first_request_offset] = size_div_4 as u8;
            } else {
                let x = first_request_offset;
                buf[x] = 0x7f;
                // safe to cast here, x <= 0xff_ff_ff < u64::MAX
                LittleEndian::write_uint(&mut buf[x+1..x+4], size_div_4 as u64, 3);
            }

            tryf!(serde_mtproto::to_writer(&mut buf[msg_offset..], &message));

            buf
        };

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

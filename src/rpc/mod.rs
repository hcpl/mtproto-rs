use std::cmp;
use std::fs::File;
use std::io::Read;
use std::mem;
use std::path::Path;

use chrono::{DateTime, Timelike, TimeZone, Utc};
use either::Either;
use erased_serde::Serialize as ErasedSerialize;
use openssl::hash;
use serde::de::{Deserialize, DeserializeSeed, DeserializeOwned};
use serde_mtproto::{Boxed, Identifiable, MtProtoSized, WithSize};
use toml;

use error::{self, ErrorKind};
use schema::FutureSalt;


pub mod encryption;
pub mod message;
pub mod utils;

use rpc::encryption::AuthKey;
use rpc::message::{DecryptedData, Message, MessageSeed, MessageType};
use tl::dynamic::TLObject;


pub trait RpcFunction: ErasedSerialize {
    type Reply: TLObject + 'static;
}

fn sha1_bytes(parts: &[&[u8]]) -> error::Result<Vec<u8>> {
    let mut hasher = hash::Hasher::new(hash::MessageDigest::sha1())?;
    for part in parts {
        hasher.update(part)?;
    }

    let bytes = hasher.finish2().map(|b| b.to_vec())?;

    Ok(bytes)
}


fn next_message_id() -> i64 {
    let time = Utc::now();
    let timestamp = time.timestamp();
    let nano = time.nanosecond() as i64; // from u32

    ((timestamp << 32) | (nano & 0x_ffff_fffc))
}


#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AppInfo {
    api_id: i32,
    // FIXME: use &'a str or Cow<'a, str> here
    api_hash: String,
}

impl AppInfo {
    pub fn new(api_id: i32, api_hash: String) -> AppInfo {
        AppInfo {
            api_id: api_id,
            api_hash: api_hash,
        }
    }

    pub fn load_from_toml(value: toml::Value) -> error::Result<AppInfo> {
        AppInfo::deserialize(value).map_err(Into::into)
    }

    pub fn load_from_toml_str(s: &str) -> error::Result<AppInfo> {
        toml::from_str(s).map_err(Into::into)
    }

    pub fn load_from_toml_file<P: AsRef<Path>>(path: P) -> error::Result<AppInfo> {
        let mut buf = String::new();
        let mut file = File::open(path)?;

        file.read_to_string(&mut buf)?;
        let app_info = toml::from_str(&buf)?;

        Ok(app_info)
    }
}


#[derive(Debug, Clone)]
pub struct Salt {
    valid_since: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    salt: i64,
}

impl From<FutureSalt> for Salt {
    fn from(fs: FutureSalt) -> Self {
        Salt {
            valid_since: Utc.timestamp(fs.valid_since as i64, 0), // from i32
            valid_until: Utc.timestamp(fs.valid_until as i64, 0), // same here
            salt: fs.salt,
        }
    }
}


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MessagePurpose {
    Content,
    NonContent,
}

// We use signed integers here because that's the default integer representation in MTProto;
// by trying to match representations we can synchronize the range of allowed values
#[derive(Debug)]
pub struct Session {
    session_id: i64,
    //temp_session_id: Option<i64>    // Not used (yet)
    server_salts: Vec<Salt>,
    seq_no: i32,
    auth_key: Option<AuthKey>,
    to_ack: Vec<i64>,
    app_info: AppInfo,
}

impl Session {
    pub fn new(session_id: i64, app_info: AppInfo) -> Session {
        Session {
            session_id: session_id,
            server_salts: Vec::new(),
            seq_no: 0,
            auth_key: None,
            to_ack: Vec::new(),
            app_info: app_info,
        }
    }

    fn next_seq_no(&mut self, purpose: MessagePurpose) -> i32 {
        match purpose {
            MessagePurpose::Content => {
                let result = self.seq_no | 1;

                let (new_seq_no, overflowed) = self.seq_no.overflowing_add(2);
                self.seq_no = new_seq_no;

                if overflowed {
                    // TODO: log overflow
                }

                result
            },
            MessagePurpose::NonContent => {
                self.seq_no
            },
        }
    }

    fn latest_server_salt(&mut self) -> error::Result<i64> {
        let time = {
            let last_salt: &Salt = self.server_salts.last().ok_or(error::Error::from(ErrorKind::NoServerSalts))?;

            // Make sure at least one salt is retained.
            cmp::min(Utc::now(), last_salt.valid_until.clone())
        };

        self.server_salts.retain(|s| &s.valid_until >= &time);
        assert!(self.server_salts.len() >= 1);
        let salt = self.server_salts[0].salt;

        Ok(salt)
    }

    pub fn add_server_salts<S, I>(&mut self, salts: I)
        where S: Into<Salt>,
              I: IntoIterator<Item = S>
    {
        self.server_salts.extend(salts.into_iter().map(Into::into));
        self.server_salts.sort_by(|a, b| a.valid_since.cmp(&b.valid_since));
    }

    pub fn adopt_key(&mut self, auth_key: AuthKey) {
        self.auth_key = Some(auth_key);
    }

    pub fn ack_id(&mut self, id: i64) {
        self.to_ack.push(id);
    }

    fn fresh_auth_key(&self) -> error::Result<AuthKey> {
        match self.auth_key {
            Some(ref key) => Ok(key.clone()),
            None => bail!(ErrorKind::NoAuthKey),
        }
    }

    pub fn create_message<T>(&mut self,
                             body: T,
                             msg_type: MessageType)
                            -> error::Result<Either<Message<T>, Message<::schema::MessageContainer>>>
        where T: ::tl::dynamic::TLObject
    {
        let message = match msg_type {
            MessageType::PlainText => {
                Either::Left(Message::PlainText {
                    message_id: next_message_id(),
                    body: WithSize::new(Boxed::new(body))?,
                })
            },
            MessageType::Encrypted => {
                if self.to_ack.is_empty() {
                    let message = self.impl_create_decrypted_message(body, MessagePurpose::Content)?;

                    Either::Left(message)
                } else {
                    let acks = ::schema::MsgsAck {
                        msg_ids: Boxed::new(mem::replace(&mut self.to_ack, vec![])),
                    };

                    let msg_container = ::schema::MessageContainer {
                        messages: vec![
                            ::schema::Message {
                                msg_id: next_message_id(),
                                seqno: self.next_seq_no(MessagePurpose::NonContent),
                                bytes: acks.size_hint()? as i32, // FIXME: safe cast
                                body: Boxed::new(Box::new(acks)),
                            },
                            ::schema::Message {
                                msg_id: next_message_id(),
                                seqno: self.next_seq_no(MessagePurpose::Content),
                                bytes: body.size_hint()? as i32, // FIXME: safe cast
                                body: Boxed::new(Box::new(body)),
                            }
                        ],
                    };

                    let msg_container_id = msg_container.messages[1].msg_id;
                    let mut message = self.impl_create_decrypted_message(msg_container, MessagePurpose::Content)?;
                    match *&mut message {
                        Message::PlainText { .. } => unreachable!(),
                        Message::Decrypted { ref mut decrypted_data } => decrypted_data.message_id = msg_container_id,
                    }

                    Either::Right(message)
                }
            },
        };

        Ok(message)
    }

    fn impl_create_decrypted_message<T>(&mut self, body: T, purpose: MessagePurpose) -> error::Result<Message<T>>
        where T: Identifiable + MtProtoSized
    {
        let decrypted_data = DecryptedData {
            salt: self.latest_server_salt()?,
            session_id: self.session_id,
            message_id: next_message_id(),
            seq_no: self.next_seq_no(purpose),
            body: WithSize::new(Boxed::new(body))?,

            key: self.fresh_auth_key()?,
        };

        let message = Message::Decrypted {
            decrypted_data: decrypted_data,
        };

        Ok(message)
    }

    pub fn process_message<T>(&self, message_bytes: &[u8], encrypted_data_len: Option<u32>) -> error::Result<Message<T>>
        where T: DeserializeOwned
    {
        use serde_mtproto::Deserializer;

        let mut deserializer = Deserializer::new(message_bytes, None);
        let seed = MessageSeed::new(self.auth_key.clone(), encrypted_data_len);

        seed.deserialize(&mut deserializer).map_err(Into::into)
    }
}

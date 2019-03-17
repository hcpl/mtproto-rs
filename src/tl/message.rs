//! Message-related definitions.

use std::fmt;
use std::marker::PhantomData;

use arrayref::array_ref;
use byteorder::{ByteOrder, LittleEndian};
use log::debug;
use rand::{self, RngCore};
use serde::de::{self, Deserialize, DeserializeOwned, DeserializeSeed, Deserializer, Error as DeError};
use serde::ser::Serialize;
use serde_derive::Serialize;
use serde_mtproto::{self, Boxed, Identifiable, MtProtoSized, UnsizedByteBuf, UnsizedByteBufSeed, WithSize};
use serde_mtproto_derive::MtProtoSized;

use crate::crypto;
use crate::crypto::hash::{sha1_from_bytes, sha256_from_bytes};
use crate::error::{self, ErrorKind};
use crate::protocol::ProtocolVersion;
use crate::utils::{
    little_endian_i128_from_array,
    safe_uint_cast,
};


#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct MessagePlain<T> {
    message_id: i64,
    body: WithSize<Boxed<T>>,
}

#[derive(Debug, Serialize, MtProtoSized)]
#[cfg_attr(test, derive(PartialEq))]
pub struct RawMessagePlain {
    auth_key_id: i64,
    message_id: i64,
    message_data_len: u32,
    message_data: UnsizedByteBuf,
}

impl<T: Identifiable + MtProtoSized> MessagePlain<T> {
    pub fn into_body(self) -> T {
        self.body.into_inner().into_inner()
    }
}

impl<T: Serialize + Identifiable + MtProtoSized> MessagePlain<T> {
    pub fn to_raw(&self) -> error::Result<RawMessagePlain> {
        let Self { message_id, ref body } = *self;

        let message_data_len = safe_uint_cast::<usize, u32>(body.inner().size_hint()?)?;
        let message_data = UnsizedByteBuf::new(serde_mtproto::to_bytes(body.inner())?)?;

        debug!("Resulting message data: len = {} --- {:?}", message_data_len, message_data);

        Ok(RawMessagePlain {
            auth_key_id: 0,
            message_id,
            message_data_len,
            message_data,
        })
    }
}

impl<T: fmt::Debug + DeserializeOwned + Identifiable + MtProtoSized> MessagePlain<T> {
    pub fn from_raw(raw: &RawMessagePlain, enum_variant_ids: &[&'static str]) -> error::Result<Self> {
        let RawMessagePlain {
            auth_key_id,
            message_id,
            message_data_len,
            ref message_data,
        } = *raw;

        if auth_key_id != 0 {
            // FIXME: return a non-zero plain message auth key id error
            panic!("auth key id is not zero");
        }

        if message_data_len != safe_uint_cast::<usize, u32>(message_data.size_hint()?)? {
            panic!("message data length mismatch");  // FIXME
        }

        let body_inner = serde_mtproto::from_bytes(message_data.inner(), enum_variant_ids)?;
        debug!("Resulting body: {:?}", body_inner);

        let body = WithSize::new(body_inner)
            .unwrap_or_else(|_| unreachable!("message data length should be no more than 0xFFFF_FFFF"));

        Ok(Self { message_id, body })
    }
}

impl<'de> Deserialize<'de> for RawMessagePlain {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        struct RawMessagePlainVisitor;

        impl<'de> de::Visitor<'de> for RawMessagePlainVisitor {
            type Value = RawMessagePlain;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("raw message data")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<RawMessagePlain, A::Error>
                where A: de::SeqAccess<'de>
            {
                let auth_key_id = seq.next_element()?.ok_or_else(|| unimplemented!())?;
                let message_id = seq.next_element()?.ok_or_else(|| unimplemented!())?;
                let message_data_len = seq.next_element()?.ok_or_else(|| unimplemented!())?;

                let message_data_len_usize = safe_uint_cast::<u32, usize>(message_data_len)
                    .map_err(A::Error::custom)?;
                let message_data_seed = UnsizedByteBufSeed::new(message_data_len_usize)
                    .map_err(A::Error::custom)?;
                let message_data = seq.next_element_seed(message_data_seed)?.ok_or_else(|| unimplemented!())?;

                Ok(RawMessagePlain { auth_key_id, message_id, message_data_len, message_data })
            }
        }

        deserializer.deserialize_struct(
            "RawMessagePlain",
            &[
                "auth_key_id",
                "message_id",
                "message_data_len",
                "message_data",
            ],
            RawMessagePlainVisitor,
        )
    }
}


#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct Message<T> {
    data: MessageData<T>,
}

#[derive(Debug, Serialize, MtProtoSized)]
#[cfg_attr(test, derive(PartialEq))]
pub struct RawMessage {
    auth_key_id: i64,
    msg_key: i128,
    encrypted_data: UnsizedByteBuf,
}

#[derive(Debug)]
pub struct RawMessageSeed {
    encrypted_data_len: usize,
}

impl<T: Identifiable + MtProtoSized> Message<T> {
    pub fn into_body(self) -> T {
        self.data.body.into_inner().into_inner()
    }
}

impl<T: Serialize + Identifiable + MtProtoSized> Message<T> {
    pub fn to_raw(&self, raw_key: &[u8; 256], version: ProtocolVersion) -> error::Result<RawMessage> {
        let Self { ref data } = *self;

        let data_raw = data.to_raw(version)?;
        let data_serialized = serde_mtproto::to_bytes(&data_raw)?;

        pack_message(&data_serialized, raw_key, version)
    }
}

impl<T: DeserializeOwned + Identifiable + MtProtoSized> Message<T> {
    pub fn from_raw(
        raw: &RawMessage,
        raw_key: &[u8; 256],
        version: ProtocolVersion,
    ) -> error::Result<Self> {
        let data_serialized = unpack_message(&raw, raw_key, version)?;

        let data_seed = RawMessageDataSeed { version };
        let data_raw = serde_mtproto::from_bytes_seed(data_seed, &data_serialized, &[])?;
        let data = MessageData::from_raw(&data_raw, version)?;

        Ok(Self { data })
    }
}

impl<'de> DeserializeSeed<'de> for RawMessageSeed {
    type Value = RawMessage;

    fn deserialize<D>(self, deserializer: D) -> Result<RawMessage, D::Error>
        where D: Deserializer<'de>
    {
        struct RawMessageVisitor {
            encrypted_data_len: usize,
        }

        impl<'de> de::Visitor<'de> for RawMessageVisitor {
            type Value = RawMessage;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("raw message")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<RawMessage, A::Error>
                where A: de::SeqAccess<'de>
            {
                //TODO: add more info to error data
                let errconv = |kind: ErrorKind| A::Error::custom(error::Error::from(kind));

                let auth_key_id = seq.next_element()?
                    .ok_or_else(|| errconv(ErrorKind::NotEnoughFields("RawMessage", 0)))?;

                if auth_key_id == 0 {
                    // TODO: warn about `auth_key_id` being zero since
                    // (only warn since this is a raw message --- error
                    // reporting can be handled afterwards)
                }

                let msg_key = seq.next_element()?
                    .ok_or_else(|| errconv(ErrorKind::NotEnoughFields("RawMessage", 1)))?;

                let seed = UnsizedByteBufSeed::new(self.encrypted_data_len).map_err(A::Error::custom)?;
                let encrypted_data = seq.next_element_seed(seed)?
                    .ok_or_else(|| errconv(ErrorKind::NotEnoughFields("RawMessage", 2)))?;

                Ok(RawMessage {
                    auth_key_id,
                    msg_key,
                    encrypted_data,
                })
            }
        }

        deserializer.deserialize_struct(
            "RawMessage",
            &[
                "auth_key_id",
                "msg_key",
                "encrypted_data",
            ],
            RawMessageVisitor { encrypted_data_len: self.encrypted_data_len },
        )
    }
}


#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq))]
pub struct MessageData<T> {
    salt: i64,
    session_id: i64,
    message_id: i64,
    seq_no: u32,
    body: WithSize<Boxed<T>>,
}

#[derive(Debug, Serialize, MtProtoSized)]
pub struct RawMessageData {
    salt: i64,
    session_id: i64,
    message_id: i64,
    seq_no: u32,
    message_data_len: u32,
    message_data: UnsizedByteBuf,
    padding: UnsizedByteBuf,
}

#[derive(Debug)]
pub struct RawMessageDataSeed {
    version: ProtocolVersion,
}

#[cfg(test)]
impl PartialEq for RawMessageData {
    fn eq(&self, other: &Self) -> bool {
        self.salt == other.salt
            && self.session_id == other.session_id
            && self.message_id == other.message_id
            && self.seq_no == other.seq_no
            && self.message_data_len == other.message_data_len
            && self.message_data == other.message_data
    }
}

impl <T: Serialize + Identifiable + MtProtoSized> MessageData<T> {
    pub fn to_raw(&self, version: ProtocolVersion) -> error::Result<RawMessageData> {
        let Self {
            salt,
            session_id,
            message_id,
            seq_no,
            ref body,
        } = *self;

        let message_data_len = safe_uint_cast::<usize, u32>(body.inner().size_hint()?)?;
        let message_data_bytes = serde_mtproto::to_bytes(body.inner())?;
        let message_data = UnsizedByteBuf::new(message_data_bytes)?;

        let data_size = salt.size_hint()?
            + session_id.size_hint()?
            + message_id.size_hint()?
            + seq_no.size_hint()?
            + message_data_len.size_hint()?
            + message_data.size_hint()?;

        let padding_size = compute_padding_size(data_size, version);
        let mut padding = vec![0; padding_size];
        rand::thread_rng().fill_bytes(&mut padding);

        let raw = RawMessageData {
            salt,
            session_id,
            message_id,
            seq_no,
            message_data_len,
            message_data,
            padding: UnsizedByteBuf::new(padding)?,
        };

        Ok(raw)
    }
}

impl<T: DeserializeOwned + Identifiable + MtProtoSized> MessageData<T> {
    pub fn from_raw(raw: &RawMessageData, version: ProtocolVersion) -> error::Result<Self> {
        let RawMessageData {
            salt,
            session_id,
            message_id,
            seq_no,
            message_data_len,
            ref message_data,
            ref padding,
        } = *raw;

        check_padding_size(padding.inner().len(), version)?;
        // TODO: check validity of `salt`, `session_id`, `message_id` and `seq_no`

        if message_data_len != safe_uint_cast::<usize, u32>(message_data.size_hint()?)? {
            unimplemented!();
        }

        let body_inner = serde_mtproto::from_bytes(message_data.inner(), &[])?;
        let body = WithSize::new(body_inner)
            .unwrap_or_else(|_| unreachable!("message data length should be no more than 0xFFFF_FFFF"));

        Ok(MessageData {
            salt,
            session_id,
            message_id,
            seq_no,
            body,
        })
    }
}

impl<'de> DeserializeSeed<'de> for RawMessageDataSeed {
    type Value = RawMessageData;

    fn deserialize<D>(self, deserializer: D) -> Result<RawMessageData, D::Error>
        where D: Deserializer<'de>
    {
        struct RawMessageDataVisitor {
            version: ProtocolVersion,
        }

        impl<'de> de::Visitor<'de> for RawMessageDataVisitor {
            type Value = RawMessageData;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("raw message data")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<RawMessageData, A::Error>
                where A: de::SeqAccess<'de>
            {
                let salt: i64 = seq.next_element()?.ok_or_else(|| unimplemented!())?;
                let session_id: i64 = seq.next_element()?.ok_or_else(|| unimplemented!())?;
                let message_id: i64 = seq.next_element()?.ok_or_else(|| unimplemented!())?;
                let seq_no: u32 = seq.next_element()?.ok_or_else(|| unimplemented!())?;
                let message_data_len: u32 = seq.next_element()?.ok_or_else(|| unimplemented!())?;

                assert!(message_data_len % 4 == 0 && message_data_len >= 8);  // FIXME
                let message_data_len_usize = safe_uint_cast::<u32, usize>(message_data_len)
                    .map_err(A::Error::custom)?;
                let message_data_seed = UnsizedByteBufSeed::new(message_data_len_usize)
                    .map_err(A::Error::custom)?;
                let message_data = seq.next_element_seed(message_data_seed)?
                    .ok_or_else(|| unimplemented!())?;

                let data_size = salt.size_hint().map_err(A::Error::custom)?
                    + session_id.size_hint().map_err(A::Error::custom)?
                    + message_id.size_hint().map_err(A::Error::custom)?
                    + seq_no.size_hint().map_err(A::Error::custom)?
                    + message_data_len.size_hint().map_err(A::Error::custom)?
                    + message_data.size_hint().map_err(A::Error::custom)?;

                let padding_size = compute_padding_size(data_size, self.version);
                let padding_seed = UnsizedByteBufSeed::new(padding_size).map_err(A::Error::custom)?;
                let padding = seq.next_element_seed(padding_seed)?.ok_or_else(|| unimplemented!())?;

                Ok(RawMessageData {
                    salt,
                    session_id,
                    message_id,
                    seq_no,
                    message_data_len,
                    message_data,
                    padding,
                })
            }
        }

        deserializer.deserialize_struct(
            "RawMessageData",
            &[
                "salt",
                "session_id",
                "message_id",
                "seq_no",
                "message_data_len",
                "message_data",
                "padding",
            ],
            RawMessageDataVisitor { version: self.version },
        )
    }
}


fn compute_padding_size(encrypted_data_len: usize, version: ProtocolVersion) -> usize {
    match version {
        ProtocolVersion::V1 => (16 - encrypted_data_len % 16) % 16,
        ProtocolVersion::V2 => (20 - encrypted_data_len % 16) % 16 + 12,
    }
}

fn check_padding_size(padding_len: usize, version: ProtocolVersion) -> error::Result<()> {
    match version {
        ProtocolVersion::V1 => assert!(padding_len < 16),  // FIXME
        ProtocolVersion::V2 => assert!(12 <= padding_len && padding_len < 28),  // FIXME
    }

    Ok(())
}


fn pack_message(
    data_serialized: &[u8],
    raw_key: &[u8; 256],
    version: ProtocolVersion,
) -> error::Result<RawMessage> {
    match version {
        ProtocolVersion::V1 => pack_message_v1(data_serialized, raw_key),
        ProtocolVersion::V2 => pack_message_v2(data_serialized, raw_key),
    }
}

fn pack_message_v1(data_serialized: &[u8], raw_key: &[u8; 256]) -> error::Result<RawMessage> {
    let raw_key_sha1 = sha1_from_bytes(&[raw_key])?;
    let auth_key_id = LittleEndian::read_i64(array_ref!(raw_key_sha1, 12, 8));

    let msg_key_large = sha1_from_bytes(&[data_serialized])?;
    let msg_key = little_endian_i128_from_array(array_ref!(msg_key_large, 4, 16));

    let aes_params = crypto::aes::calc_aes_params_encrypt_v1(raw_key, msg_key)?;
    let encrypted_data = crypto::aes::aes_ige_encrypt(&aes_params, data_serialized);

    Ok(RawMessage {
        auth_key_id,
        msg_key,
        encrypted_data: UnsizedByteBuf::new(encrypted_data)?,
    })
}

fn pack_message_v2(data_serialized: &[u8], raw_key: &[u8; 256]) -> error::Result<RawMessage> {
    let raw_key_sha1 = sha1_from_bytes(&[raw_key])?;
    let auth_key_id = LittleEndian::read_i64(array_ref!(raw_key_sha1, 12, 8));

    let msg_key_large = sha256_from_bytes(&[array_ref!(raw_key, 88, 32), data_serialized])?;
    let msg_key = little_endian_i128_from_array(array_ref!(msg_key_large, 8, 16));

    let aes_params = crypto::aes::calc_aes_params_encrypt_v2(raw_key, msg_key)?;
    let encrypted_data = crypto::aes::aes_ige_encrypt(&aes_params, data_serialized);

    Ok(RawMessage {
        auth_key_id,
        msg_key,
        encrypted_data: UnsizedByteBuf::new(encrypted_data)?,
    })
}


fn unpack_message(
    raw_msg: &RawMessage,
    raw_key: &[u8; 256],
    version: ProtocolVersion,
) -> error::Result<Vec<u8>> {
    match version {
        ProtocolVersion::V1 => unpack_message_v1(raw_msg, raw_key),
        ProtocolVersion::V2 => unpack_message_v2(raw_msg, raw_key),
    }
}

fn unpack_message_v1(raw_msg: &RawMessage, raw_key: &[u8; 256]) -> error::Result<Vec<u8>> {
    let RawMessage { auth_key_id, msg_key, ref encrypted_data } = *raw_msg;

    let raw_key_sha1 = sha1_from_bytes(&[raw_key])?;
    let auth_key_id_checked = LittleEndian::read_i64(array_ref!(raw_key_sha1, 12, 8));

    if auth_key_id != auth_key_id_checked {
        // TODO: auth key mismatch
        unimplemented!();
    }

    let aes_params = crypto::aes::calc_aes_params_decrypt_v1(raw_key, msg_key)?;
    let data_serialized = crypto::aes::aes_ige_decrypt(&aes_params, encrypted_data.inner());

    let msg_key_large = sha1_from_bytes(&[&data_serialized])?;
    let msg_key_checked = little_endian_i128_from_array(array_ref!(msg_key_large, 4, 16));

    if msg_key != msg_key_checked {
        // TODO: msg key mismatch
        unimplemented!();
    }

    Ok(data_serialized)
}

fn unpack_message_v2(raw_msg: &RawMessage, raw_key: &[u8; 256]) -> error::Result<Vec<u8>> {
    let RawMessage { auth_key_id, msg_key, ref encrypted_data } = *raw_msg;

    let raw_key_sha1 = sha1_from_bytes(&[raw_key])?;
    let auth_key_id_checked = LittleEndian::read_i64(array_ref!(raw_key_sha1, 12, 8));

    if auth_key_id != auth_key_id_checked {
        // TODO: auth key mismatch
        unimplemented!();
    }

    let aes_params = crypto::aes::calc_aes_params_decrypt_v2(raw_key, msg_key)?;
    let data_serialized = crypto::aes::aes_ige_decrypt(&aes_params, encrypted_data.inner());

    let msg_key_large = sha256_from_bytes(&[array_ref!(raw_key, 88 + 8, 32), &data_serialized])?;
    let msg_key_checked = little_endian_i128_from_array(array_ref!(msg_key_large, 8, 16));

    if msg_key != msg_key_checked {
        // TODO: msg key mismatch
        unimplemented!();
    }

    Ok(data_serialized)
}


pub trait MessageCommon<T>: fmt::Debug + Sized + Send + private::MessageCommonSealed {
    type Raw: RawMessageCommon<Seed = Self::RawSeed>;
    type RawSeed: for<'de> RawMessageSeedCommon<'de, Value = Self::Raw>;

    fn new(
        salt: i64,
        session_id: i64,
        message_id: i64,
        seq_no: u32,
        obj: T,
    ) -> Result<Self, (T, error::Error)>;

    fn to_raw(
        &self,
        raw_key: Option<&[u8; 256]>,
        version: ProtocolVersion,
    ) -> error::Result<Self::Raw>
        where T: Serialize;

    fn from_raw(
        raw: &Self::Raw,
        raw_key: Option<&[u8; 256]>,
        version: ProtocolVersion,
        enum_variant_ids: &[&'static str],
    ) -> error::Result<Self>
        where T: DeserializeOwned;

    fn set_message_id(&mut self, message_id: i64);

    fn into_body(self) -> T;
}

impl<T> MessageCommon<T> for MessagePlain<T>
    where T: fmt::Debug + Identifiable + MtProtoSized + Send
{
    type Raw = RawMessagePlain;
    type RawSeed = PhantomData<RawMessagePlain>;

    fn new(
        _salt: i64,
        _session_id: i64,
        message_id: i64,
        _seq_no: u32,
        obj: T,
    ) -> Result<Self, (T, error::Error)> {
        // Rely on the fact that
        // `<T as Identifiable>::type_id(obj) == <&T as Identifiable>::type_id(&obj)`
        // and
        // `<Boxed<T> as MtProtoSized>::size_hint(Boxed::new(obj))
        //     == <Boxed<&T> as MtProtoSized>::size_hint(Boxed::new(&obj))`
        match WithSize::new(Boxed::new(&obj)) {
            Ok(_) => Ok(MessagePlain {
                message_id,
                body: WithSize::new(Boxed::new(obj)).unwrap_or_else(|_| unreachable!()),
            }),
            Err(e) => Err((obj, e.into())),
        }
    }

    fn to_raw(
        &self,
        _raw_key: Option<&[u8; 256]>,
        _version: ProtocolVersion,
    ) -> error::Result<RawMessagePlain>
        where T: Serialize
    {
        self.to_raw()
    }

    fn from_raw(
        raw: &RawMessagePlain,
        _raw_key: Option<&[u8; 256]>,
        _version: ProtocolVersion,
        enum_variant_ids: &[&'static str],
    ) -> error::Result<Self>
        where T: DeserializeOwned
    {
        // NOTE: `Self::from_raw` triggers rustc error E0061 --- probably
        // because the compiler associates `Self` only with the `MessageCommon`
        // trait and not with `MessagePlain` as well
        MessagePlain::from_raw(raw, enum_variant_ids)
    }

    fn set_message_id(&mut self, message_id: i64) {
        self.message_id = message_id;
    }

    fn into_body(self) -> T {
        self.into_body()
    }
}

impl<T> MessageCommon<T> for Message<T>
    where T: fmt::Debug + Identifiable + MtProtoSized + Send
{
    type Raw = RawMessage;
    type RawSeed = RawMessageSeed;

    fn new(
        salt: i64,
        session_id: i64,
        message_id: i64,
        seq_no: u32,
        obj: T,
    ) -> Result<Self, (T, error::Error)> {
        // Rely on the fact that
        // `<T as Identifiable>::type_id(obj) == <&T as Identifiable>::type_id(&obj)`
        // and
        // `<Boxed<T> as MtProtoSized>::size_hint(Boxed::new(obj))
        //     == <Boxed<&T> as MtProtoSized>::size_hint(Boxed::new(&obj))`
        match WithSize::new(Boxed::new(&obj)) {
            Ok(_) => Ok(Message {
                data: MessageData {
                    salt,
                    session_id,
                    message_id,
                    seq_no,
                    body: WithSize::new(Boxed::new(obj)).unwrap_or_else(|_| unreachable!()),
                },
            }),
            Err(e) => Err((obj, e.into())),
        }
    }

    fn to_raw(
        &self,
        raw_key: Option<&[u8; 256]>,
        version: ProtocolVersion,
    ) -> error::Result<RawMessage>
        where T: Serialize
    {
        self.to_raw(raw_key.as_ref().unwrap(), version)  // FIXME
    }

    fn from_raw(
        raw: &RawMessage,
        raw_key: Option<&[u8; 256]>,
        version: ProtocolVersion,
        _enum_variant_ids: &[&'static str],
    ) -> error::Result<Self>
        where T: DeserializeOwned
    {
        Self::from_raw(raw, raw_key.as_ref().unwrap(), version)  // FIXME
    }

    fn set_message_id(&mut self, message_id: i64) {
        self.data.message_id = message_id;
    }

    fn into_body(self) -> T {
        self.into_body()
    }
}


pub trait RawMessageCommon:
    fmt::Debug + Serialize + MtProtoSized + Send + 'static + private::RawMessageCommonSealed
{
    type Seed: for<'de> RawMessageSeedCommon<'de, Value = Self>;

    fn encrypted_data_len(len: usize) -> Option<usize>;
}

impl RawMessageCommon for RawMessagePlain {
    type Seed = PhantomData<RawMessagePlain>;

    fn encrypted_data_len(_len: usize) -> Option<usize> {
        None
    }
}

impl RawMessageCommon for RawMessage {
    type Seed = RawMessageSeed;

    fn encrypted_data_len(len: usize) -> Option<usize> {
        Some(len - 24)
    }
}


pub trait RawMessageSeedCommon<'de>: DeserializeSeed<'de> + Sized + private::RawMessageSeedCommonSealed {
    fn new(encrypted_data_len: Option<usize>) -> Self;
}

impl<'de> RawMessageSeedCommon<'de> for PhantomData<RawMessagePlain> {
    fn new(_encrypted_data_len: Option<usize>) -> Self {
        PhantomData
    }
}

impl<'de> RawMessageSeedCommon<'de> for RawMessageSeed {
    fn new(encrypted_data_len: Option<usize>) -> Self {
        RawMessageSeed { encrypted_data_len: encrypted_data_len.unwrap() }
    }
}


mod private {
    use super::*;


    pub trait MessageCommonSealed {}

    impl<T> MessageCommonSealed for MessagePlain<T> {}
    impl<T> MessageCommonSealed for Message<T> {}


    pub trait RawMessageCommonSealed {}

    impl RawMessageCommonSealed for RawMessagePlain {}
    impl RawMessageCommonSealed for RawMessage {}


    pub trait RawMessageSeedCommonSealed {}

    impl RawMessageSeedCommonSealed for PhantomData<RawMessagePlain> {}
    impl RawMessageSeedCommonSealed for RawMessageSeed {}
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_plain_roundtrip() {
        let msg_plain = MessagePlain {
            message_id: 0xFFFF,
            body: WithSize::new(Boxed::new("foo".to_owned())).unwrap(),
        };

        const RAW_MSG_PLAIN_SERIALIZED: &[u8] = &[
            0, 0, 0, 0, 0, 0, 0, 0,
            0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            8, 0, 0, 0,
            0x24, 0x6e, 0x28, 0xb5,
            3, b'f', b'o', b'o',
        ];

        let raw_msg_plain = msg_plain.to_raw().unwrap();
        let raw_msg_plain_serialized = serde_mtproto::to_bytes(&raw_msg_plain).unwrap();

        assert_eq!(raw_msg_plain_serialized, RAW_MSG_PLAIN_SERIALIZED);

        let raw_msg_plain2 = serde_mtproto::from_bytes(&raw_msg_plain_serialized, &[]).unwrap();

        assert_eq!(raw_msg_plain, raw_msg_plain2);

        let msg_plain2 = MessagePlain::from_raw(&raw_msg_plain, &[]).unwrap();

        assert_eq!(msg_plain, msg_plain2);
    }

    #[test]
    fn message_roundtrip() {
        let msg = Message {
            data: MessageData {
                salt: -0xFFFF,
                session_id: 0x1000_0000,
                message_id: 0,
                seq_no: 100,
                body: WithSize::new(Boxed::new("bar".to_owned())).unwrap(),
            },
        };

        let raw_key = array_int! {
            16 => b"Long long key...",
            240 => &[0; 240],
        };

        fn do_roundtrip(msg: &Message<String>, raw_key: &[u8; 256], version: ProtocolVersion) {
            let raw_msg = msg.to_raw(raw_key, version).unwrap();
            let raw_msg_serialized = serde_mtproto::to_bytes(&raw_msg).unwrap();
            let raw_msg_deserialized = {
                let encrypted_data_len = raw_msg.encrypted_data.inner().len();
                let max_u32_as_usize = safe_uint_cast::<u32, usize>(u32::max_value()).unwrap();
                assert!(encrypted_data_len <= max_u32_as_usize);
                let raw_msg_seed = RawMessageSeed { encrypted_data_len };

                serde_mtproto::from_bytes_seed(raw_msg_seed, &raw_msg_serialized, &[]).unwrap()
            };

            assert_eq!(raw_msg, raw_msg_deserialized);

            //let msg_deserialized = Message::from_raw(raw_msg_deserialized, raw_key, version).unwrap();

            //assert_eq!(msg, &msg_deserialized);
        }

        do_roundtrip(&msg, &raw_key, ProtocolVersion::V1);
        do_roundtrip(&msg, &raw_key, ProtocolVersion::V2);
    }

    #[test]
    fn message_data_roundtrip() {
        let msg_data = MessageData {
            salt: -200,
            session_id: 10000,
            message_id: i64::min_value(),
            seq_no: u32::max_value(),
            body: WithSize::new(Boxed::new("baz".to_owned())).unwrap(),
        };

        const RAW_MSG_DATA_SERIALIZED: &[u8] = &[
            56, 255, 255, 255, 255, 255, 255, 255,
            16, 39, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 128,
            255, 255, 255, 255,
            8, 0, 0, 0,
            0x24, 0x6e, 0x28, 0xb5,
            3, b'b', b'a', b'z',
        ];

        fn do_roundtrip(msg_data: &MessageData<String>, version: ProtocolVersion) {
            let raw_msg_data = msg_data.to_raw(version).unwrap();
            let raw_msg_data_seed = RawMessageDataSeed { version };
            let raw_msg_data_serialized = serde_mtproto::to_bytes(&raw_msg_data).unwrap();

            let padding_offset = match version {
                ProtocolVersion::V1 => (16 - RAW_MSG_DATA_SERIALIZED.len() % 16) % 16,
                ProtocolVersion::V2 => (20 - RAW_MSG_DATA_SERIALIZED.len() % 16) % 16 + 12,
            };

            let padding_pos = raw_msg_data_serialized.len() - padding_offset;
            assert_eq!(&raw_msg_data_serialized[0..padding_pos], RAW_MSG_DATA_SERIALIZED);

            let raw_msg_data_deserialized =
                serde_mtproto::from_bytes_seed(raw_msg_data_seed, &raw_msg_data_serialized, &[]).unwrap();

            assert_eq!(raw_msg_data, raw_msg_data_deserialized);

            let msg_data_deserialized =
                MessageData::from_raw(&raw_msg_data_deserialized, version).unwrap();

            assert_eq!(msg_data, &msg_data_deserialized);
        }

        do_roundtrip(&msg_data, ProtocolVersion::V1);
        do_roundtrip(&msg_data, ProtocolVersion::V2);
    }
}

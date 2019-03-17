use std::io::Read;

use flate2::Compression;
use flate2::read::{GzDecoder as GzDecoderRead, GzEncoder as GzEncoderRead};
use serde::de::{Deserialize, Deserializer, DeserializeOwned, Error as DeError};
use serde::ser::{Error as SerError, Serialize, Serializer};
use serde_bytes::ByteBuf;
use serde_derive::{Serialize, Deserialize};
use serde_mtproto::{self, Boxed, MtProtoSized};
use serde_mtproto_derive::MtProtoIdentifiable;

use crate::error;


#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GzipPacked<T> {
    data: T,
}

#[derive(Serialize, Deserialize, MtProtoIdentifiable)]
#[mtproto_identifiable(id = "0x3072cfa1")]
struct GzipPackedHelper {
    byte_buf: ByteBuf,
}

impl<T> GzipPacked<T> {
    pub fn new(data: T) -> Self {
        GzipPacked { data }
    }

    pub fn into_inner(self) -> T {
        self.data
    }
}

impl<T: Serialize> Serialize for GzipPacked<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        let bytes = serde_mtproto::to_bytes(&self.data).map_err(S::Error::custom)?;

        let mut encoder = GzEncoderRead::new(bytes.as_slice(), Compression::default());
        let mut compressed = Vec::new();
        encoder.read_to_end(&mut compressed).map_err(S::Error::custom)?;

        Boxed::new(GzipPackedHelper { byte_buf: ByteBuf::from(compressed) }).serialize(serializer)
    }
}

impl<'de, T: DeserializeOwned> Deserialize<'de> for GzipPacked<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        let packed = Boxed::<GzipPackedHelper>::deserialize(deserializer)?;
        let compressed: Vec<u8> = packed.into_inner().byte_buf.into();

        let mut decoder = GzDecoderRead::new(compressed.as_slice());
        let mut bytes = Vec::new();
        decoder.read_to_end(&mut bytes).map_err(D::Error::custom)?;

        let data = serde_mtproto::from_bytes(&bytes, &[]).map_err(D::Error::custom)?;

        Ok(GzipPacked { data })
    }
}


#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[serde(bound(deserialize = "T: DeserializeOwned"))]
pub enum OptionallyGzipPacked<T> {
    Packed(GzipPacked<T>),
    Plain(T),
}

impl<T: MtProtoSized> OptionallyGzipPacked<T> {
    pub fn new(data: T) -> error::Result<Self> {
        if data.size_hint()? > 512 {
            Ok(OptionallyGzipPacked::Packed(GzipPacked::new(data)))
        } else {
            Ok(OptionallyGzipPacked::Plain(data))
        }
    }

    pub fn into_inner(self) -> T {
        match self {
            OptionallyGzipPacked::Packed(packed) => packed.into_inner(),
            OptionallyGzipPacked::Plain(data) => data,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gzip_packed_roundtrip() {
        let gzip_packed = GzipPacked::new("foo".to_owned());
        let gzip_packed_serialized = serde_mtproto::to_bytes(&gzip_packed).unwrap();
        let gzip_packed_deserialized = serde_mtproto::from_bytes(&gzip_packed_serialized, &[]).unwrap();

        assert_eq!(gzip_packed, gzip_packed_deserialized);
    }
}

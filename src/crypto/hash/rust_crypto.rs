use std::ops;

use digest::{
    Digest,
    generic_array::{GenericArray, typenum},
};
use sha1::Sha1;
use sha2::Sha256;

use crate::error;


#[derive(Debug)]
pub(crate) struct Sha1DigestBytes(GenericArray<u8, typenum::U20>);

impl ops::Deref for Sha1DigestBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.deref()
    }
}

pub(crate) fn sha1_from_bytes(parts: &[&[u8]]) -> error::Result<Sha1DigestBytes> {
    let mut sh = Sha1::default();

    for part in parts {
        sh.input(part);
    }

    let digest = sh.result();
    Ok(Sha1DigestBytes(digest))
}


#[derive(Debug)]
pub(crate) struct Sha256DigestBytes(GenericArray<u8, typenum::U32>);

impl ops::Deref for Sha256DigestBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.deref()
    }
}

pub(crate) fn sha256_from_bytes(parts: &[&[u8]]) -> error::Result<Sha256DigestBytes> {
    let mut sh = Sha256::default();

    for part in parts {
        sh.input(part);
    }

    let digest = sh.result();
    Ok(Sha256DigestBytes(digest))
}

use std::ops;

use openssl::hash;

use crate::error;


#[derive(Debug)]
pub(crate) struct Sha1DigestBytes(hash::DigestBytes);

impl ops::Deref for Sha1DigestBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.deref()
    }
}

pub(crate) fn sha1_from_bytes(parts: &[&[u8]]) -> error::Result<Sha1DigestBytes> {
    let mut hasher = hash::Hasher::new(hash::MessageDigest::sha1())?;

    for part in parts {
        hasher.update(part)?;
    }

    let digest = hasher.finish()?;
    Ok(Sha1DigestBytes(digest))
}


#[derive(Debug)]
pub(crate) struct Sha256DigestBytes(hash::DigestBytes);

impl ops::Deref for Sha256DigestBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.0.deref()
    }
}

pub(crate) fn sha256_from_bytes(parts: &[&[u8]]) -> error::Result<Sha256DigestBytes> {
    let mut hasher = hash::Hasher::new(hash::MessageDigest::sha256())?;

    for part in parts {
        hasher.update(part)?;
    }

    let digest = hasher.finish()?;
    Ok(Sha256DigestBytes(digest))
}

use openssl::hash;

use ::error;


pub(crate) fn sha1_from_bytes(parts: &[&[u8]]) -> error::Result<hash::DigestBytes> {
    let mut hasher = hash::Hasher::new(hash::MessageDigest::sha1())?;
    for part in parts {
        hasher.update(part)?;
    }
    hasher.finish().map_err(Into::into)
}

pub(crate) fn sha256_from_bytes(parts: &[&[u8]]) -> error::Result<hash::DigestBytes> {
    let mut hasher = hash::Hasher::new(hash::MessageDigest::sha256())?;
    for part in parts {
        hasher.update(part)?;
    }
    hasher.finish().map_err(Into::into)
}

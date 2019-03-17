use error_chain::bail;
use rand::{self, RngCore};

use crate::crypto::{
    hash::sha1_from_bytes,
    rsa::RsaPublicKey,
};
use crate::error::{self, ErrorKind};


/// RSA public key stored as **X.509 SubjectPublicKeyInfo/OpenSSL PEM
/// public key**.
///
/// Relevant StackOverflow answer which explains why it's called like
/// that: https://stackoverflow.com/a/29707204.
pub const KNOWN_RAW_KEYS: &[&str] = &[
    "\
-----BEGIN PUBLIC KEY-----\n\
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwVACPi9w23mF3tBkdZz+\n\
zwrzKOaaQdr01vAbU4E1pvkfj4sqDsm6lyDONS789sVoD/xCS9Y0hkkC3gtL1tSf\n\
TlgCMOOul9lcixlEKzwKENj1Yz/s7daSan9tqw3bfUV/nqgbhGX81v/+7RFAEd+R\n\
wFnK7a+XYl9sluzHRyVVaTTveB2GazTwEfzk2DWgkBluml8OREmvfraX3bkHZJTK\n\
X4EQSjBbbdJ2ZXIsRrYOXfaA+xayEGB+8hdlLmAjbCVfaigxX0CDqWeR1yFL9kwd\n\
9P0NsZRPsmoqVwMbMu7mStFai6aIhc3nSlv8kg9qv1m6XHVQY3PnEw+QQtqSIXkl\n\
HwIDAQAB\n\
-----END PUBLIC KEY-----",
];


pub(super) fn prepare_encrypt(input: &[u8]) -> error::Result<[u8; 256]> {
    let sha1 = sha1_from_bytes(&[input])?;

    if sha1.len() + input.len() > 255 {
        bail!(ErrorKind::Sha1Total255Longer);
    }

    // OpenSSL requires exactly 256 bytes
    let mut res = [0; 256];

    {
        let (res_first_byte, rest) = res.split_at_mut(1);
        let (res_sha1, rest2) = rest.split_at_mut(20);
        let (res_input, res_padding) = rest2.split_at_mut(input.len());

        assert!(res_first_byte == [0]);
        res_sha1.copy_from_slice(&sha1);
        res_input.copy_from_slice(input);
        rand::thread_rng().fill_bytes(res_padding);
    }

    Ok(res)
}


/// Find a key fingerprint of which can be found in the supplied
/// sequence of fingerprints.
pub(crate) fn find_first_key(input_fingerprints: &[i64]) -> error::Result<(RsaPublicKey, i64)> {
    for raw_key in KNOWN_RAW_KEYS {
        let cooked_key = RsaPublicKey::new(raw_key)?;
        let fingerprint = cooked_key.fingerprint()?;

        if input_fingerprints.contains(&fingerprint) {
            return Ok((cooked_key, fingerprint));
        }
    }

    Err(ErrorKind::NoRsaPublicKeyForFingerprints(input_fingerprints.to_vec()).into())
}

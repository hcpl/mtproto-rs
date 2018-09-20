use std::fmt;

use byteorder::{ByteOrder, LittleEndian};
use openssl::{bn, pkey, rsa};
use rand::{self, RngCore};
use serde_bytes::ByteBuf;
use serde_mtproto;

use ::crypto::hash::sha1_from_bytes;
use ::error::{self, ErrorKind};


/// "Cooked" RSA key.
pub struct RsaPublicKey(rsa::Rsa<pkey::Public>);

impl RsaPublicKey {
    pub fn new(raw_key: &[u8]) -> error::Result<Self> {
        rsa::Rsa::public_key_from_pem(raw_key)
            .map(RsaPublicKey)
            .map_err(Into::into)
    }

    pub fn sha1_fingerprint(&self) -> error::Result<[u8; 20]> {
        let mut buf = Vec::new();

        let n_bytes = self.0.n().to_vec();
        let e_bytes = self.0.e().to_vec();

        // Need to allocate new space, so use `&mut buf` instead of `buf.as_mut_slice()`
        serde_mtproto::to_writer(&mut buf, &ByteBuf::from(n_bytes))?;
        serde_mtproto::to_writer(&mut buf, &ByteBuf::from(e_bytes))?;

        let sha1_fingerprint = array_int! {
            20 => &sha1_from_bytes(&[&buf])?,
        };

        Ok(sha1_fingerprint)
    }

    pub fn fingerprint(&self) -> error::Result<i64> {
        let sha1_fingerprint = self.sha1_fingerprint()?;
        let fingerprint = LittleEndian::read_i64(&sha1_fingerprint[12..20]);

        Ok(fingerprint)
    }

    pub fn encrypt(&self, input: &[u8]) -> error::Result<[u8; 256]> {
        let padded_input = prepare_encrypt(input)?;
        debug!("Padded input: {:?}", &padded_input[..]);

        let mut output = [0; 256];
        self.0.public_encrypt(&padded_input, &mut output, rsa::Padding::NONE)?;

        Ok(output)
    }
}

fn prepare_encrypt(input: &[u8]) -> error::Result<[u8; 256]> {
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


/// RSA public key stored as **X.509 SubjectPublicKeyInfo/OpenSSL PEM
/// public key**.
///
/// Relevant StackOverflow answer which explains why it's called like
/// that: https://stackoverflow.com/a/29707204.
pub const KNOWN_RAW_KEYS: &[&[u8]] = &[
    b"\
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

/// Find a key fingerprint of which can be found in the supplied
/// sequence of fingerprints.
pub fn find_first_key(input_fingerprints: &[i64]) -> error::Result<(RsaPublicKey, i64)> {
    for raw_key in KNOWN_RAW_KEYS {
        let cooked_key = RsaPublicKey::new(raw_key)?;
        let fingerprint = cooked_key.fingerprint()?;

        if input_fingerprints.contains(&fingerprint) {
            return Ok((cooked_key, fingerprint));
        }
    }

    Err(ErrorKind::NoRsaPublicKeyForFingerprints(input_fingerprints.to_vec()).into())
}


// The `impl fmt::Debug for rsa::Rsa<T>` only writes "Rsa".
// We want to output more information when debugging (even though it's unsafe).
impl fmt::Debug for RsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        struct StrDebugAsDisplay<'a>(&'a str);

        impl<'a> fmt::Debug for StrDebugAsDisplay<'a> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                fmt::Display::fmt(self.0, f)
            }
        }

        struct RsaRepr<'a> {
            n: &'a bn::BigNumRef,
            e: &'a bn::BigNumRef,
        }

        impl<'a> fmt::Debug for RsaRepr<'a> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                let debug_big_num = |big_num: &bn::BigNumRef| {
                    match big_num.to_hex_str() {
                        Ok(hex_str) => hex_str.to_lowercase(),
                        Err(_) => big_num.to_vec().iter()
                            .map(|byte| format!("{:02x}", byte)).collect::<String>(),
                    }
                };

                f.debug_struct("RsaRepr")
                    .field("n", &StrDebugAsDisplay(&debug_big_num(self.n)))
                    .field("e", &StrDebugAsDisplay(&debug_big_num(self.e)))
                    .finish()
            }
        }

        let rsa_repr = RsaRepr {
            n: self.0.n(),
            e: self.0.e(),
        };

        f.debug_tuple("RsaPublicKey")
            .field(&rsa_repr)
            .finish()
    }
}

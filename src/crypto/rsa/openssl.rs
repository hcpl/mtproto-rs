use std::fmt;

use byteorder::{ByteOrder, LittleEndian};
use log::debug;
use openssl::{bn, pkey, rsa};
use serde_bytes::ByteBuf;
use serde_mtproto;

use crate::crypto::{
    hash::sha1_from_bytes,
    rsa::common,
};
use crate::error;


/// "Cooked" RSA key.
pub(crate) struct RsaPublicKey(rsa::Rsa<pkey::Public>);

impl RsaPublicKey {
    pub(crate) fn new(raw_key: &str) -> error::Result<Self> {
        rsa::Rsa::public_key_from_pem(raw_key.as_bytes())
            .map(RsaPublicKey)
            .map_err(Into::into)
    }

    pub(crate) fn sha1_fingerprint(&self) -> error::Result<[u8; 20]> {
        let n_bytes = self.0.n().to_vec();
        let e_bytes = self.0.e().to_vec();

        let n_bytes_size = serde_mtproto::size_hint_from_byte_seq_len(n_bytes.len())?;
        let e_bytes_size = serde_mtproto::size_hint_from_byte_seq_len(e_bytes.len())?;

        let mut buf = vec![0; n_bytes_size + e_bytes_size];

        serde_mtproto::to_writer(&mut buf[..n_bytes_size], &ByteBuf::from(n_bytes))?;
        serde_mtproto::to_writer(&mut buf[n_bytes_size..], &ByteBuf::from(e_bytes))?;

        let sha1_fingerprint = array_int! {
            20 => &sha1_from_bytes(&[&buf])?,
        };

        Ok(sha1_fingerprint)
    }

    pub(crate) fn fingerprint(&self) -> error::Result<i64> {
        let sha1_fingerprint = self.sha1_fingerprint()?;
        let fingerprint = LittleEndian::read_i64(&sha1_fingerprint[12..20]);

        Ok(fingerprint)
    }

    pub(crate) fn encrypt(&self, input: &[u8]) -> error::Result<[u8; 256]> {
        let padded_input = common::prepare_encrypt(input)?;
        debug!("Padded input: {:?}", &padded_input[..]);

        let mut output = [0; 256];
        self.0.public_encrypt(&padded_input, &mut output, rsa::Padding::NONE)?;

        Ok(output)
    }
}


// The `impl fmt::Debug for rsa::Rsa<T>` only writes "Rsa".
// We want to output more information when debugging (even though it's unsafe).
impl fmt::Debug for RsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        struct StrDebugAsDisplay<'a>(&'a str);

        impl<'a> fmt::Debug for StrDebugAsDisplay<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                fmt::Display::fmt(self.0, f)
            }
        }

        struct RsaRepr<'a> {
            n: &'a bn::BigNumRef,
            e: &'a bn::BigNumRef,
        }

        impl<'a> fmt::Debug for RsaRepr<'a> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                let debug_big_num = |big_num: &bn::BigNumRef| {
                    match big_num.to_hex_str() {
                        Ok(hex_str) => hex_str.to_lowercase(),
                        Err(_) => big_num.to_vec()
                            .iter()
                            .map(|byte| format!("{:02x}", byte))
                            .collect::<String>(),
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

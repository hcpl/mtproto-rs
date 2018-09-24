use std::fmt;

use base64;
use byteorder::{ByteOrder, LittleEndian};
use der_parser::{self, BitStringObject, DerObject, DerObjectContent};
use nom;
use num_bigint::BigUint;
use serde_bytes::ByteBuf;
use serde_mtproto;

use ::crypto::{
    hash::sha1_from_bytes,
    rsa::common,
};
use ::error::{self, ErrorKind};


/// "Cooked" RSA key.
pub(crate) struct RsaPublicKey {
    n: BigUint,
    e: BigUint,
}

impl RsaPublicKey {
    pub(crate) fn new(raw_key: &str) -> error::Result<Self> {
        let decoded = key_base64_decoded(raw_key)?;
        let (n, e) = key_parse_der(&decoded)?;

        Ok(RsaPublicKey { n, e })
    }

    pub(crate) fn sha1_fingerprint(&self) -> error::Result<[u8; 20]> {
        let n_bytes = self.n.to_bytes_be();
        let e_bytes = self.e.to_bytes_be();

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

        let bn_padded_input = BigUint::from_bytes_be(&padded_input);
        let pre_output = BigUint::modpow(&bn_padded_input, &self.e, &self.n).to_bytes_be();

        let mut output = [0; 256];
        output[(256 - pre_output.len())..].copy_from_slice(&pre_output);

        Ok(output)
    }
}


fn key_base64_decoded(raw_key: &str) -> error::Result<[u8; 294]> {
    const BEGIN_PK: &str = "-----BEGIN PUBLIC KEY-----";
    const END_PK: &str = "-----END PUBLIC KEY-----";

    let begin_pos = raw_key.find(BEGIN_PK)
        .ok_or_else(|| ErrorKind::RsaPublicKeyInvalid(raw_key.to_owned()))? + BEGIN_PK.len() + 1;
    let end_pos = raw_key.rfind(END_PK)
        .ok_or_else(|| ErrorKind::RsaPublicKeyInvalid(raw_key.to_owned()))?;

    let mut res = [0; 294];

    {
        let raw_lines = raw_key[begin_pos..end_pos].split('\n');
        let decoded_lines = res.chunks_mut(48);

        for (raw_line, decoded_line) in raw_lines.zip(decoded_lines) {
            base64::decode_config_slice(raw_line, base64::STANDARD, decoded_line)?;
        }
    }

    Ok(res)
}

fn key_parse_der(decoded: &[u8; 294]) -> error::Result<(BigUint, BigUint)> {
    let (rest, outer) = parse_der_owned(decoded)?;

    if rest.len() != 0 {
        unimplemented!();  // FIXME: invalid pubkey error
    }

    let bit_string = as_bitstring_ref(&as_sequence(&outer)?[1])?;
    let (rest2, inner) = parse_der_owned(&bit_string.data)?;

    if rest2.len() != 0 {
        unimplemented!();  // FIXME: invalid pubkey error
    }

    let seq = as_sequence(&inner)?;

    let n = BigUint::from_bytes_be(as_integer(&seq[0])?);
    let e = BigUint::from_bytes_be(as_integer(&seq[1])?);

    Ok((n, e))
}

fn parse_der_owned(i: &[u8]) -> error::Result<(&[u8], DerObject)> {
    der_parser::parse_der(i).map_err(|e| map_nom_err(e, ToOwned::to_owned).into())
}

fn map_nom_err<T, U, F>(nom_err: nom::Err<T>, f: F) -> nom::Err<U>
where
    F: Fn(T) -> U,
{
    match nom_err {
        nom::Err::Incomplete(needed) => nom::Err::Incomplete(needed),
        nom::Err::Error(ctx) => nom::Err::Error(map_nom_context(ctx, f)),
        nom::Err::Failure(ctx) => nom::Err::Failure(map_nom_context(ctx, f)),
    }
}

fn map_nom_context<T, U, F>(nom_ctx: nom::Context<T>, f: F) -> nom::Context<U>
where
    F: Fn(T) -> U,
{
    match nom_ctx {
        nom::Context::Code(input, kind) => nom::Context::Code(f(input), kind),
        nom::Context::List(vec) => {
            let new_vec = vec.into_iter().map(|(input, kind)| (f(input), kind)).collect();
            nom::Context::List(new_vec)
        },
    }
}

// Custom functions that mirror methods of `DerObject`.
// They are needed because we can't use `DerError` in `error-chain` as
// `error-chain`-generated code requires `DerError: Error + Display`

fn as_sequence<'a>(der_obj: &'a DerObject) -> error::Result<&'a Vec<DerObject<'a>>> {
    match der_obj.content {
        DerObjectContent::Sequence(ref s) => Ok(s),
        _ => unimplemented!(),
    }
}

fn as_bitstring_ref<'a>(der_obj: &'a DerObject) -> error::Result<&'a BitStringObject<'a>> {
    match der_obj.content {
        DerObjectContent::BitString(_, ref b) => Ok(b),
        _ => unimplemented!(),
    }
}

fn as_integer<'a>(der_obj: &'a DerObject) -> error::Result<&'a [u8]> {
    match der_obj.content {
        DerObjectContent::Integer(ref b) => Ok(b),
        _ => unimplemented!(),
    }
}


impl fmt::Debug for RsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        struct StrDebugAsDisplay<'a>(&'a str);

        impl<'a> fmt::Debug for StrDebugAsDisplay<'a> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                fmt::Display::fmt(self.0, f)
            }
        }

        f.debug_struct("RsaPublicKey")
            .field("n", &StrDebugAsDisplay(&format!("{:x}", self.n)))
            .field("e", &StrDebugAsDisplay(&format!("{:x}", self.e)))
            .finish()
    }
}

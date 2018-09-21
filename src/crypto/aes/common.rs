use ::crypto::hash::{sha1_from_bytes, sha256_from_bytes};
use ::error;
use ::utils::little_endian_i128_into_array;


#[derive(Debug)]
pub(crate) struct AesParams {
    pub(crate) key: [u8; 32],
    pub(crate) iv: [u8; 32],
}

enum Mode { Encrypt, Decrypt }


pub(crate) fn calc_aes_params_encrypt_v1(
    auth_key_raw: &[u8; 256],
    msg_key: i128,
) -> error::Result<AesParams> {
    calc_aes_params_v1(auth_key_raw, msg_key, Mode::Encrypt)
}

pub(crate) fn calc_aes_params_decrypt_v1(
    auth_key_raw: &[u8; 256],
    msg_key: i128,
) -> error::Result<AesParams> {
    calc_aes_params_v1(auth_key_raw, msg_key, Mode::Decrypt)
}

fn calc_aes_params_v1(
    auth_key_raw: &[u8; 256],
    msg_key: i128,
    mode: Mode,
) -> error::Result<AesParams> {
    let msg_key_bytes = little_endian_i128_into_array(msg_key);

    let mut pos = match mode {
        Mode::Encrypt => 0,
        Mode::Decrypt => 8,
    };

    let mut auth_key_take = |len| {
        let ret = &auth_key_raw[pos..pos+len];
        pos += len;
        ret
    };

    let sha1_a = sha1_from_bytes(&[&msg_key_bytes, auth_key_take(32)])?;
    let sha1_b = sha1_from_bytes(&[auth_key_take(16), &msg_key_bytes, auth_key_take(16)])?;
    let sha1_c = sha1_from_bytes(&[auth_key_take(32), &msg_key_bytes])?;
    let sha1_d = sha1_from_bytes(&[&msg_key_bytes, auth_key_take(32)])?;

    Ok(AesParams {
        key: array_int! { 8  => &sha1_a[0..8],  12 => &sha1_b[8..20], 12 => &sha1_c[4..16] },
        iv:  array_int! { 12 => &sha1_a[8..20], 8  => &sha1_b[0..8],  4  => &sha1_c[16..20], 8 => &sha1_d[0..8] },
    })
}


pub(crate) fn calc_aes_params_encrypt_v2(
    auth_key_raw: &[u8; 256],
    msg_key: i128,
) -> error::Result<AesParams> {
    calc_aes_params_v2(auth_key_raw, msg_key, Mode::Encrypt)
}

pub(crate) fn calc_aes_params_decrypt_v2(
    auth_key_raw: &[u8; 256],
    msg_key: i128,
) -> error::Result<AesParams> {
    calc_aes_params_v2(auth_key_raw, msg_key, Mode::Decrypt)
}

fn calc_aes_params_v2(
    auth_key_raw: &[u8; 256],
    msg_key: i128,
    mode: Mode,
) -> error::Result<AesParams> {
    let msg_key_bytes = little_endian_i128_into_array(msg_key);

    let mut pos = match mode {
        Mode::Encrypt => 0,
        Mode::Decrypt => 8,
    };

    let mut auth_key_take = |len| {
        let ret = &auth_key_raw[pos..pos+len];
        pos += len;
        ret
    };

    let sha256_a = sha256_from_bytes(&[&msg_key_bytes, auth_key_take(36)])?;
    auth_key_take(4);
    let sha256_b = sha256_from_bytes(&[auth_key_take(36), &msg_key_bytes])?;

    Ok(AesParams {
        key: array_int! { 8 => &sha256_a[0..8], 16 => &sha256_b[8..24], 8 => &sha256_a[24..32] },
        iv:  array_int! { 8 => &sha256_b[0..8], 16 => &sha256_a[8..24], 8 => &sha256_b[24..32] },
    })
}

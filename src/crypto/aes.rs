use openssl::{aes, symm};

use ::crypto::hash::{sha1_from_bytes, sha256_from_bytes};
use ::error;
use ::utils::little_endian_i128_into_array;


#[derive(Debug)]
pub(crate) struct AesParams {
    pub(crate) key: [u8; 32],
    pub(crate) iv: [u8; 32],
}


pub(crate) fn aes_ige_encrypt(aes_params: &AesParams, data_serialized: &[u8]) -> Vec<u8> {
    assert!(data_serialized.len() % 16 == 0);

    let mut encrypted_data = vec![0; data_serialized.len()];
    let aes_key = aes::AesKey::new_encrypt(&aes_params.key).unwrap();  // Key is 256-bit => can unwrap

    // Must not panic because:
    // - data_serialized.len() == encrypted_data.len() by declaration of encrypted_data
    // - data_serialized.len() % 16 == 0
    // - aes_params.iv.len() == 32 >= 32
    aes::aes_ige(
        data_serialized,
        &mut encrypted_data,
        &aes_key,
        &mut aes_params.iv.clone(),
        symm::Mode::Encrypt,
    );

    encrypted_data
}

pub(crate) fn aes_ige_decrypt(aes_params: &AesParams, encrypted_data: &[u8]) -> Vec<u8> {
    assert!(encrypted_data.len() % 16 == 0);

    let mut data_serialized = vec![0; encrypted_data.len()];
    let aes_key = aes::AesKey::new_decrypt(&aes_params.key).unwrap();  // Key is 256-bit => can unwrap

    // Must not panic because:
    // - encrypted_data.len() == data_serialized.len() by declaration of data_serialized
    // - encrypted_data.len() % 16 == 0
    // - aes_params.iv.len() == 32 >= 32
    aes::aes_ige(
        encrypted_data,
        &mut data_serialized,
        &aes_key,
        &mut aes_params.iv.clone(),
        symm::Mode::Decrypt,
    );

    data_serialized
}


pub(crate) fn calc_aes_params_encrypt_v1(
    auth_key_raw: &[u8; 256],
    msg_key: i128,
) -> error::Result<AesParams> {
    calc_aes_params_v1(auth_key_raw, msg_key, symm::Mode::Encrypt)
}

pub(crate) fn calc_aes_params_decrypt_v1(
    auth_key_raw: &[u8; 256],
    msg_key: i128,
) -> error::Result<AesParams> {
    calc_aes_params_v1(auth_key_raw, msg_key, symm::Mode::Decrypt)
}

fn calc_aes_params_v1(
    auth_key_raw: &[u8; 256],
    msg_key: i128,
    mode: symm::Mode,
) -> error::Result<AesParams> {
    let msg_key_bytes = little_endian_i128_into_array(msg_key);

    let mut pos = match mode {
        symm::Mode::Encrypt => 0,
        symm::Mode::Decrypt => 8,
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
    calc_aes_params_v2(auth_key_raw, msg_key, symm::Mode::Encrypt)
}

pub(crate) fn calc_aes_params_decrypt_v2(
    auth_key_raw: &[u8; 256],
    msg_key: i128,
) -> error::Result<AesParams> {
    calc_aes_params_v2(auth_key_raw, msg_key, symm::Mode::Decrypt)
}

fn calc_aes_params_v2(
    auth_key_raw: &[u8; 256],
    msg_key: i128,
    mode: symm::Mode,
) -> error::Result<AesParams> {
    let msg_key_bytes = little_endian_i128_into_array(msg_key);

    let mut pos = match mode {
        symm::Mode::Encrypt => 0,
        symm::Mode::Decrypt => 8,
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

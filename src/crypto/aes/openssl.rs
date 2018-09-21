use openssl::{aes, symm};

use ::crypto::aes::common::AesParams;


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

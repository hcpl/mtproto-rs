use aes::{
    block_cipher_trait::{
        generic_array::GenericArray,
        BlockCipher,
    },
    Aes256,
};

use ::crypto::aes::common::AesParams;


pub(crate) fn aes_ige_encrypt(aes_params: &AesParams, data_serialized: &[u8]) -> Vec<u8> {
    assert!(data_serialized.len() % 16 == 0);

    let mut encrypted_data = vec![0; data_serialized.len()];

    aes_ige_encrypt_impl(
        data_serialized,
        &mut encrypted_data,
        &aes_params.key,
        &mut aes_params.iv.clone(),
    );

    encrypted_data
}

pub(crate) fn aes_ige_decrypt(aes_params: &AesParams, encrypted_data: &[u8]) -> Vec<u8> {
    assert!(encrypted_data.len() % 16 == 0);

    let mut data_serialized = vec![0; encrypted_data.len()];

    aes_ige_decrypt_impl(
        encrypted_data,
        &mut data_serialized,
        &aes_params.key,
        &mut aes_params.iv.clone(),
    );

    data_serialized
}


const AES_BLOCK_SIZE: usize = 16;
const AES256_KEY_SIZE: usize = 32;

fn aes_ige_encrypt_impl(
    input: &[u8],
    output: &mut [u8],
    aes_key: &[u8; AES256_KEY_SIZE],
    ivec: &mut [u8; AES_BLOCK_SIZE * 2],
) {
    assert!(input.len() % AES_BLOCK_SIZE == 0);
    assert_eq!(input.len(), output.len());

    if input.len() == 0 {
        return;
    }

    let key = Aes256::new(GenericArray::from_slice(aes_key));
    let (iv, iv2) = ivec.split_at_mut(AES_BLOCK_SIZE);

    for (input_block, output_block) in input.chunks(AES_BLOCK_SIZE).zip(output.chunks_mut(AES_BLOCK_SIZE)) {
        let mut tmp2 = array_int! { AES_BLOCK_SIZE => input_block };
        for (tmp2_byte, iv_byte) in tmp2.iter_mut().zip(iv.iter()) {
            *tmp2_byte ^= iv_byte;
        }

        key.encrypt_block(GenericArray::from_mut_slice(&mut tmp2));

        for (tmp2_byte, iv2_byte) in tmp2.iter_mut().zip(iv2.iter()) {
            *tmp2_byte ^= iv2_byte;
        }

        output_block.copy_from_slice(&tmp2);

        iv.copy_from_slice(&tmp2);
        iv2.copy_from_slice(input_block);
    }
}

fn aes_ige_decrypt_impl(
    input: &[u8],
    output: &mut [u8],
    aes_key: &[u8; AES256_KEY_SIZE],
    ivec: &mut [u8; AES_BLOCK_SIZE * 2],
) {
    assert!(input.len() % AES_BLOCK_SIZE == 0);
    assert_eq!(input.len(), output.len());

    if input.len() == 0 {
        return;
    }

    let key = Aes256::new(GenericArray::from_slice(aes_key));
    let (iv, iv2) = ivec.split_at_mut(AES_BLOCK_SIZE);

    for (input_block, output_block) in input.chunks(AES_BLOCK_SIZE).zip(output.chunks_mut(AES_BLOCK_SIZE)) {
        let mut tmp = array_int! { AES_BLOCK_SIZE => input_block };
        for (tmp_byte, iv2_byte) in tmp.iter_mut().zip(iv2.iter()) {
            *tmp_byte ^= iv2_byte;
        }

        key.decrypt_block(GenericArray::from_mut_slice(&mut tmp));

        for (tmp_byte, iv_byte) in tmp.iter_mut().zip(iv.iter()) {
            *tmp_byte ^= iv_byte;
        }

        output_block.copy_from_slice(&tmp);

        iv.copy_from_slice(input_block);
        iv2.copy_from_slice(&tmp);
    }
}

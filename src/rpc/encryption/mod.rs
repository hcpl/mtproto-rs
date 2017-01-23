use std::io::{Cursor, Write};

use byteorder::{LittleEndian, ByteOrder, WriteBytesExt};
use openssl::{aes, symm};

use rpc::functions::authz::{Nonce, PQInnerData};
use rpc::{sha1_bytes, sha1_nonces};

pub mod asymm;

pub type Result<T> = ::std::result::Result<T, ::openssl::error::ErrorStack>;

enum Padding {
    Total255,
    Mod16,
}

fn sha1_and_or_pad(input: &[u8], prepend_sha1: bool, padding: Padding) -> Result<Vec<u8>> {
    let mut ret = if prepend_sha1 {
        sha1_bytes(&[input])?
    } else {
        vec![]
    };
    ret.extend(input);
    match padding {
        Padding::Total255 => {
            while ret.len() < 255 {
                ret.push(0);
            }
        },
        Padding::Mod16 if ret.len() % 16 != 0 => {
            for _ in 0..16 - (ret.len() % 16) {
                ret.push(0);
            }
        },
        _ => (),
    }
    Ok(ret)
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AesParams {
    key: [u8; 32],
    iv: [u8; 32],
}

impl AesParams {
    fn run_ige(mut self, input: &[u8], mode: symm::Mode) -> Result<Vec<u8>> {
        let key = match mode {
            symm::Mode::Encrypt => aes::AesKey::new_encrypt(&self.key).unwrap(),
            symm::Mode::Decrypt => aes::AesKey::new_decrypt(&self.key).unwrap(),
        };
        let mut output = vec![0; input.len()];
        aes::aes_ige(input, &mut output, &key, &mut self.iv, mode);
        Ok(output)
    }

    pub fn ige_encrypt(self, decrypted: &[u8], prepend_sha1: bool) -> Result<Vec<u8>> {
        let input = sha1_and_or_pad(decrypted, prepend_sha1, Padding::Mod16)?;
        self.run_ige(&input, symm::Mode::Encrypt)
    }

    pub fn ige_decrypt(self, encrypted: &[u8]) -> Result<Vec<u8>> {
        self.run_ige(encrypted, symm::Mode::Decrypt)
    }

    pub fn from_pq_inner_data(data: &PQInnerData) -> Result<AesParams> {
        let sha1_a = sha1_nonces(&[data.new_nonce.0, data.new_nonce.1, data.server_nonce])?;
        let sha1_b = sha1_nonces(&[data.server_nonce, data.new_nonce.0, data.new_nonce.1])?;
        let sha1_c = sha1_nonces(&[
            data.new_nonce.0, data.new_nonce.1, data.new_nonce.0, data.new_nonce.1])?;
        let mut tmp = [0u8; 8];
        LittleEndian::write_u64(&mut tmp, (data.new_nonce.0).0);
        let mut ret: AesParams = Default::default();
        set_slice_parts(&mut ret.key, &[&sha1_a, &sha1_b[..12]]);
        set_slice_parts(&mut ret.iv, &[&sha1_b[12..], &sha1_c, &tmp[..4]]);
        Ok(ret)
    }
}

fn set_slice_parts(result: &mut [u8], parts: &[&[u8]]) {
    let mut cursor = Cursor::new(result);
    for part in parts {
        cursor.write(part).unwrap();
    }
}

pub struct AuthKey {
    auth_key: [u8; 256],
    aux_hash: u64,
    fingerprint: u64,
}

impl Clone for AuthKey {
    fn clone(&self) -> AuthKey {
        AuthKey {
            auth_key: self.auth_key,
            aux_hash: self.aux_hash,
            fingerprint: self.fingerprint,
        }
    }
}

impl Copy for AuthKey {}

impl AuthKey {
    pub fn new(key_in: &[u8]) -> Result<AuthKey> {
        let mut key = [0u8; 256];
        key.copy_from_slice(key_in);
        let sha1 = sha1_bytes(&[key_in])?;
        let aux_hash = LittleEndian::read_u64(&sha1[0..8]);
        let fingerprint = LittleEndian::read_u64(&sha1[12..20]);
        Ok(AuthKey {
            auth_key: key,
            aux_hash: aux_hash,
            fingerprint: fingerprint,
        })
    }

    fn generate_message_aes_params(&self, msg_key: &[u8], mode: symm::Mode) -> Result<AesParams> {
        let mut pos = match mode {
            symm::Mode::Encrypt => 0,
            symm::Mode::Decrypt => 8,
        };
        let mut auth_key_take = |len| {
            let ret = &self.auth_key[pos..pos+len];
            pos += len;
            ret
        };
        let sha1_a = sha1_bytes(&[msg_key, auth_key_take(32)])?;
        let sha1_b = sha1_bytes(&[auth_key_take(16), msg_key, auth_key_take(16)])?;
        let sha1_c = sha1_bytes(&[auth_key_take(32), msg_key])?;
        let sha1_d = sha1_bytes(&[msg_key, auth_key_take(32)])?;

        let mut ret: AesParams = Default::default();
        set_slice_parts(&mut ret.key, &[&sha1_a[0..8], &sha1_b[8..20], &sha1_c[4..16]]);
        set_slice_parts(&mut ret.iv, &[&sha1_a[8..20], &sha1_b[0..8], &sha1_c[16..20], &sha1_d[0..8]]);
        Ok(ret)
    }

    pub fn new_nonce_hash(&self, which: u8, new_nonce: (Nonce, Nonce)) -> Result<Nonce> {
        let mut input = [0u8; 41];
        {
            let mut cursor = Cursor::new(&mut input[..]);
            cursor.write_u64::<LittleEndian>((new_nonce.0).0).unwrap();
            cursor.write_u64::<LittleEndian>((new_nonce.0).1).unwrap();
            cursor.write_u64::<LittleEndian>((new_nonce.1).0).unwrap();
            cursor.write_u64::<LittleEndian>((new_nonce.1).1).unwrap();
            cursor.write_u8(which).unwrap();
            cursor.write_u64::<LittleEndian>(self.aux_hash).unwrap();
        }
        let sha1 = sha1_bytes(&[&input])?;
        Ok((LittleEndian::read_u64(&sha1[4..12]), LittleEndian::read_u64(&sha1[12..20])))
    }

    pub fn encrypt_message(&self, message: &[u8]) -> Result<Vec<u8>> {
        let message_hash = sha1_bytes(&[message])?;
        let message_key = &message_hash[4..20];
        let aes = self.generate_message_aes_params(message_key, symm::Mode::Encrypt)?;
        let mut ret = vec![0u8; 8];
        LittleEndian::write_u64(&mut ret, self.fingerprint);
        ret.extend(message_key);
        ret.extend(aes.ige_encrypt(message, false)?);
        Ok(ret)
    }

    pub fn decrypt_message(&self, message: &[u8]) -> Result<Vec<u8>> {
        assert!(LittleEndian::read_u64(&message[..8]) == self.fingerprint);
        let message_key = &message[8..24];
        let aes = self.generate_message_aes_params(message_key, symm::Mode::Decrypt)?;
        aes.ige_decrypt(&message[24..])
    }
}

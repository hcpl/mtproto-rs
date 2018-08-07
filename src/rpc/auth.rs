use byteorder::{BigEndian, ByteOrder, LittleEndian};
use chrono::Utc;
use extprim::i128;
use futures::{self, Future, Poll};
use openssl::{aes, bn, hash, symm};
use rand::{self, Rng};
use serde_mtproto::{self, Boxed, MtProtoSized};

use ::error::{self, ErrorKind};
use ::rpc::{MessageType, Session};
use ::rpc::connection::ConnectionConfig;
use ::rpc::encryption::asymm;
use ::rpc::session::SessionConnection;
use ::schema;
use ::I256;


macro_rules! bailf {
    ($e:expr) => {
        return Box::new(futures::future::err($e.into()))
    }
}

macro_rules! tryf {
    ($e:expr) => {
        match { $e } {
            Ok(v) => v,
            Err(e) => bailf!(e),
        }
    }
}

macro_rules! array_int {
    ($($len:tt => $source:expr,)+) => {{
        let mut arr = [0; 0 $(+ $len)+];
        array_int! { @iter arr [] [$($len => $source,)+] }
        arr
    }};

    (@iter
        $arr:ident
        [$($used_len:tt => $used_source:expr,)*]
        []
    ) => {};

    (@iter
        $arr:ident
        [$($used_len:tt => $used_source:expr,)*]
        [
            $first_unused_len:tt => $first_unused_source:expr,
            $($rest_unused_len:tt => $rest_unused_source:expr,)*
        ]
    ) => {
        $arr[(0 $(+ $used_len)*)..($first_unused_len $(+ $used_len)*)]
            .copy_from_slice($first_unused_source);
        array_int! { @iter
            $arr
            [
                $($used_len => $used_source,)*
                $first_unused_len => $first_unused_source,
            ]
            [$($rest_unused_len => $rest_unused_source,)*]
        }
    };
}


pub struct AuthValues {
    //pub auth_key: AuthKey,
    pub auth_key: Vec<u8>,
    pub time_offset: i32,
}

pub struct AuthFuture {
    fut: Box<Future<Item = AuthValues, Error = error::Error> + Send>,
}

impl Future for AuthFuture {
    type Item = AuthValues;
    type Error = error::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.fut.poll()
    }
}


/// Combine all authorization steps defined below.
pub fn auth_with_session(conn_config: ConnectionConfig, session: Session) -> AuthFuture {
    let fut = session.connect(conn_config)
        .map(|session_conn| Step1Input { session_conn })
        .and_then(auth_step1)
        .and_then(auth_step2)
        .and_then(auth_step3)
        .and_then(auth_step4);

    AuthFuture {
        fut: Box::new(fut),
    }
}

struct Step1Input {
    session_conn: SessionConnection,
}

/// Step 1: DH exchange initiation using PQ request
fn auth_step1(input: Step1Input)
    -> Box<Future<Item = Step2Input, Error = error::Error> + Send>
{
    let nonce = rand::random();
    let req_pq = schema::rpc::req_pq { nonce };

    info!("Sending PQ request: {:#?}", req_pq);
    let request = input.session_conn.request(req_pq, MessageType::PlainText, MessageType::PlainText);

    Box::new(request.map(move |(session_conn, res_pq)| {
        Step2Input { session_conn, res_pq, nonce }
    }))
}

struct Step2Input {
    session_conn: SessionConnection,
    res_pq: schema::ResPQ,
    nonce: i128::i128,
}

/// Step 2: Presenting PQ proof of work & server authentication
fn auth_step2(input: Step2Input)
    -> Box<Future<Item = Step3Input, Error = error::Error> + Send>
{
    fn prepare_step2(input: Step2Input)
        -> error::Result<(SessionConnection, schema::rpc::req_DH_params, i128::i128, i128::i128, I256)>
    {
        let Step2Input { session_conn, res_pq, nonce } = input;

        info!("Received PQ response: {:#?}", res_pq);

        check_nonce(nonce, res_pq.nonce)?;

        let pq_u64 = BigEndian::read_u64(&res_pq.pq);
        debug!("Decomposing pq = {}...", pq_u64);
        let (p_u32, q_u32) = asymm::decompose_pq(pq_u64)?;
        debug!("Decomposed p = {}, q = {}", p_u32, q_u32);
        let u32_to_vec = |num| {
            let mut v = vec![0; 4];
            BigEndian::write_u32(v.as_mut_slice(), num);
            v
        };
        let p = u32_to_vec(p_u32);
        let q = u32_to_vec(q_u32);
        let new_nonce = rand::random();

        let p_q_inner_data = Boxed::new(schema::P_Q_inner_data::p_q_inner_data(schema::p_q_inner_data {
            pq: res_pq.pq.clone(),
            p: p.clone().into(),
            q: q.clone().into(),
            nonce,
            server_nonce: res_pq.server_nonce,
            new_nonce,
        }));
        info!("PQ proof of work to be sent: {:#?}", &p_q_inner_data);

        let p_q_inner_data_serialized = serde_mtproto::to_bytes(&p_q_inner_data)?;
        debug!("Data bytes to send: {:?}", &p_q_inner_data_serialized);
        let known_sha1_fingerprints = asymm::KNOWN_RAW_KEYS.iter()
            .map(|raw_key| {
                let sha1_fingerprint = raw_key.read()?.sha1_fingerprint()?;
                Ok(sha1_fingerprint.iter().map(|b| format!("{:02x}", b)).collect::<String>())
            })
            .collect::<error::Result<Vec<_>>>()?;
        debug!("Known public key SHA1 fingerprints: {:?}", known_sha1_fingerprints);
        let known_fingerprints = asymm::KNOWN_RAW_KEYS.iter()
            .map(|raw_key| Ok(raw_key.read()?.fingerprint()?))
            .collect::<error::Result<Vec<_>>>()?;
        debug!("Known public key fingerprints: {:?}", known_fingerprints);
        let server_pk_fingerprints = res_pq.server_public_key_fingerprints.inner().as_slice();
        debug!("Server public key fingerprints: {:?}", &server_pk_fingerprints);
        let (rsa_public_key, fingerprint) =
            asymm::find_first_key_fail_safe(server_pk_fingerprints)?;
        debug!("RSA public key used: {:#?}", &rsa_public_key);
        let encrypted_data = rsa_public_key.encrypt(&p_q_inner_data_serialized)?;
        debug!("Encrypted data: {:?}", encrypted_data.as_ref());
        //let encrypted_data2 = rsa_public_key.encrypt2(&p_q_inner_data_serialized)?;
        //debug!("Encrypted data 2: {:?}", &encrypted_data2);

        let req_dh_params = schema::rpc::req_DH_params {
            nonce,
            server_nonce: res_pq.server_nonce,
            p: p.into(),
            q: q.into(),
            public_key_fingerprint: fingerprint,
            encrypted_data: encrypted_data.to_vec().into(),
            //encrypted_data: encrypted_data2.into(),
        };

        Ok((session_conn, req_dh_params, nonce, res_pq.server_nonce, new_nonce))
    }

    let (session_conn, req_dh_params, nonce, server_nonce, new_nonce) = tryf!(prepare_step2(input));

    info!("Sending DH key exchange request: {:?}", req_dh_params);
    let request = session_conn.request(req_dh_params, MessageType::PlainText, MessageType::PlainText);

    Box::new(request.map(move |(session_conn, server_dh_params)| {
        Step3Input {
            session_conn,
            server_dh_params,
            nonce,
            server_nonce,
            new_nonce,
        }
    }))
}

struct Step3Input {
    session_conn: SessionConnection,
    server_dh_params: schema::Server_DH_Params,
    nonce: i128::i128,
    server_nonce: i128::i128,
    new_nonce: I256,
}

/// Step 3: DH key exchange complete
fn auth_step3(input: Step3Input)
    -> Box<Future<Item = Step4Input, Error = error::Error> + Send>
{
    fn prepare_step3(input: Step3Input)
        -> error::Result<(SessionConnection, schema::rpc::set_client_DH_params, i128::i128, i128::i128, I256, Vec<u8>, i32)>
    {
        let Step3Input { session_conn, server_dh_params, nonce, server_nonce, new_nonce } = input;

        info!("Received server DH parameters: {:#?}", server_dh_params);

        match server_dh_params {
            schema::Server_DH_Params::server_DH_params_fail(server_dh_params_fail) => {
                error!("DH request failed: {:?}", server_dh_params_fail);

                check_nonce(nonce, server_dh_params_fail.nonce)?;
                check_server_nonce(server_nonce, server_dh_params_fail.server_nonce)?;
                check_new_nonce_hash(new_nonce, server_dh_params_fail.new_nonce_hash)?;

                bail!(ErrorKind::ServerDHParamsFail);
            },
            schema::Server_DH_Params::server_DH_params_ok(server_dh_params_ok) => {
                check_nonce(nonce, server_dh_params_ok.nonce)?;
                check_server_nonce(server_nonce, server_dh_params_ok.server_nonce)?;

                let server_nonce_bytes = little_endian_i128_into_array(server_nonce);
                let new_nonce_bytes = little_endian_i256_into_array(new_nonce);

                let hash1 = sha1_from_bytes(&[&new_nonce_bytes, &server_nonce_bytes])?;
                let hash2 = sha1_from_bytes(&[&server_nonce_bytes, &new_nonce_bytes])?;
                let hash3 = sha1_from_bytes(&[&new_nonce_bytes, &new_nonce_bytes])?;

                let tmp_aes_key = array_int! {
                    20 => &*hash1,
                    12 => &hash2[0..12],
                };
                let tmp_aes_iv = array_int! {
                    8  => &hash2[12..20],
                    20 => &*hash3,
                    4  => &new_nonce_bytes[0..4],
                };

                // Key is 256-bit => can unwrap safely
                let aes_decrypt_key = aes::AesKey::new_decrypt(&tmp_aes_key).unwrap();
                let mut server_dh_inner_decrypted = vec![0; server_dh_params_ok.encrypted_answer.len()];
                aes::aes_ige(server_dh_params_ok.encrypted_answer.as_ref(), server_dh_inner_decrypted.as_mut_slice(), &aes_decrypt_key, &mut tmp_aes_iv.clone(), symm::Mode::Decrypt);

                const SHA1_HASH_LENGTH: usize = 20;
                let (server_dh_inner_server_hash, server_dh_inner_bytes) =
                    server_dh_inner_decrypted.split_at(SHA1_HASH_LENGTH);
                let (server_dh_inner, random_tail) =
                    serde_mtproto::from_bytes_reuse::<Boxed<schema::Server_DH_inner_data>>(server_dh_inner_bytes, &[])?;

                let server_dh_inner_len = server_dh_inner_bytes.len() - random_tail.len();
                let server_dh_inner_client_hash =
                    sha1_from_bytes(&[&server_dh_inner_bytes[0..server_dh_inner_len]])?;
                check_sha1(server_dh_inner_server_hash, &server_dh_inner_client_hash)?;

                let server_dh_inner = server_dh_inner.into_inner();
                check_nonce(nonce, server_dh_inner.nonce)?;
                check_server_nonce(server_nonce, server_dh_inner.server_nonce)?;

                // TODO: check that `dh_prime` is actually prime
                // TODO: check that `g` is a quadratic residue modulo `p`

                let g = bn::BigNum::from_u32(server_dh_inner.g as u32)?;
                let mut b = bn::BigNum::new()?;
                b.rand(2048, bn::MsbOption::ONE, true)?;
                let dh_prime = bn::BigNum::from_slice(&server_dh_inner.dh_prime)?;
                let mut g_b = bn::BigNum::new()?;
                let mut ctx = bn::BigNumContext::new()?;
                g_b.mod_exp(&g, &b, &dh_prime, &mut ctx)?;

                let client_dh_inner = Boxed::new(schema::Client_DH_Inner_Data {
                    nonce,
                    server_nonce,
                    retry_id: 0,  // TODO: actual retry ID
                    g_b: g_b.to_vec().into(),
                });

                let client_dh_inner_len = client_dh_inner.size_hint()?;
                let random_tail_len = (16 - ((SHA1_HASH_LENGTH + client_dh_inner_len) % 16)) % 16;
                let mut client_dh_inner_to_encrypt =
                    vec![0; SHA1_HASH_LENGTH + client_dh_inner_len + random_tail_len];

                {
                    let (client_dh_inner_hash, client_dh_inner_rest) =
                        client_dh_inner_to_encrypt.split_at_mut(SHA1_HASH_LENGTH);
                    let (client_dh_inner_bytes, random_tail) =
                        client_dh_inner_rest.split_at_mut(client_dh_inner_len);
                    serde_mtproto::to_writer(&mut *client_dh_inner_bytes, &client_dh_inner)?;
                    let hash_bytes = sha1_from_bytes(&[client_dh_inner_bytes])?;
                    client_dh_inner_hash.copy_from_slice(&*hash_bytes);
                    rand::thread_rng().fill_bytes(random_tail);
                }

                // Key is 256-bit => can unwrap safely
                let aes_encrypt_key = aes::AesKey::new_encrypt(&tmp_aes_key).unwrap();
                let mut encrypted_data = vec![0; client_dh_inner_to_encrypt.len()];
                aes::aes_ige(&client_dh_inner_to_encrypt, encrypted_data.as_mut_slice(), &aes_encrypt_key, &mut tmp_aes_iv.clone(), symm::Mode::Encrypt);

                let set_client_dh_params = schema::rpc::set_client_DH_params {
                    nonce,
                    server_nonce,
                    encrypted_data: encrypted_data.into(),
                };

                let g_a = bn::BigNum::from_slice(&server_dh_inner.g_a)?;
                let mut g_ab = bn::BigNum::new()?;
                g_ab.mod_exp(&g_a, &b, &dh_prime, &mut ctx)?;
                let auth_key = g_ab.to_vec();

                // Hopefully server will use 64-bit integers before Year 2038
                // Problem kicks in
                let local_timestamp = Utc::now().timestamp() as i32;
                let time_offset = server_dh_inner.server_time - local_timestamp;

                Ok((session_conn, set_client_dh_params, nonce, server_nonce, new_nonce, auth_key, time_offset))
            },
        }
    }

    let (session_conn, set_client_dh_params, nonce, server_nonce, new_nonce, auth_key, time_offset) =
        tryf!(prepare_step3(input));

    let request = session_conn.request(set_client_dh_params, MessageType::PlainText, MessageType::PlainText);

    Box::new(request.map(move |(_session_conn, set_client_dh_params_answer)| {
        Step4Input {
            set_client_dh_params_answer,
            nonce,
            server_nonce,
            new_nonce,
            auth_key,
            time_offset,
        }
    }))
}

struct Step4Input {
    set_client_dh_params_answer: schema::Set_client_DH_params_answer,
    nonce: i128::i128,
    server_nonce: i128::i128,
    new_nonce: I256,
    auth_key: Vec<u8>,
    time_offset: i32,
}

fn auth_step4(input: Step4Input)
    -> error::Result<AuthValues>
{
    let Step4Input {
        set_client_dh_params_answer,
        nonce,
        server_nonce,
        new_nonce,
        auth_key,
        time_offset,
    } = input;

    info!("Received server DH verification: {:#?}", set_client_dh_params_answer);

    let auth_key_sha1 = sha1_from_bytes(&[&auth_key])?;
    let auth_key_aux_hash = array_int! {
        8 => &auth_key_sha1[0..8],
    };
    //let auth_key_hash = array_int! {
    //    8 => &auth_key_sha1[12..20],
    //};

    match set_client_dh_params_answer {
        schema::Set_client_DH_params_answer::dh_gen_ok(dh_gen_ok) => {
            info!("DH params verification succeeded: {:?}", dh_gen_ok);

            check_nonce(nonce, dh_gen_ok.nonce)?;
            check_server_nonce(server_nonce, dh_gen_ok.server_nonce)?;
            check_new_nonce_derived_hash(new_nonce, 1, auth_key_aux_hash, dh_gen_ok.new_nonce_hash1)?;

            Ok(AuthValues { auth_key, time_offset })
        },
        schema::Set_client_DH_params_answer::dh_gen_retry(dh_gen_retry) => {
            info!("DH params verification needs a retry: {:?}", dh_gen_retry);

            check_nonce(nonce, dh_gen_retry.nonce)?;
            check_server_nonce(server_nonce, dh_gen_retry.server_nonce)?;
            check_new_nonce_derived_hash(new_nonce, 2, auth_key_aux_hash, dh_gen_retry.new_nonce_hash2)?;

            // TODO: implement DH retries
            unimplemented!();
        },
        schema::Set_client_DH_params_answer::dh_gen_fail(dh_gen_fail) => {
            error!("DH params verification failed: {:?}", dh_gen_fail);

            check_nonce(nonce, dh_gen_fail.nonce)?;
            check_server_nonce(server_nonce, dh_gen_fail.server_nonce)?;
            check_new_nonce_derived_hash(new_nonce, 3, auth_key_aux_hash, dh_gen_fail.new_nonce_hash3)?;

            bail!(ErrorKind::SetClientDHParamsAnswerFail);
        },
    }
}


// ===== UTILS ===== //

fn little_endian_i128_from_array(arr: &[u8; 16]) -> i128::i128 {
    let lo = LittleEndian::read_u64(&arr[0..8]);
    let hi = LittleEndian::read_i64(&arr[8..16]);
    i128::i128::from_parts(hi, lo)
}

fn little_endian_i128_into_array(n: i128::i128) -> [u8; 16] {
    let mut arr = [0; 16];
    LittleEndian::write_u64(&mut arr[0..8], n.low64());
    LittleEndian::write_i64(&mut arr[8..16], n.high64());
    arr
}

fn little_endian_i256_into_array(n: I256) -> [u8; 32] {
    let mut arr = [0; 32];
    little_endian_i256_to_array(&mut arr, n);
    arr
}

fn little_endian_i256_to_array(arr: &mut [u8; 32], n: I256) {
    LittleEndian::write_u64(&mut arr[0..8], n.low128().low64());
    LittleEndian::write_u64(&mut arr[8..16], n.low128().high64());
    LittleEndian::write_u64(&mut arr[16..24], n.high128().low64());
    LittleEndian::write_i64(&mut arr[24..32], n.high128().high64());
}

fn sha1_from_bytes(bytes: &[&[u8]]) -> error::Result<hash::DigestBytes> {
    let mut hasher = hash::Hasher::new(hash::MessageDigest::sha1())?;
    for b in bytes {
        hasher.update(b)?;
    }
    hasher.finish().map_err(Into::into)
}

fn check_nonce(expected: i128::i128, found: i128::i128) -> error::Result<()> {
     if expected != found {
         bail!(ErrorKind::NonceMismatch(expected, found));
     }

     Ok(())
}

fn check_server_nonce(expected: i128::i128, found: i128::i128) -> error::Result<()> {
     if expected != found {
         bail!(ErrorKind::ServerNonceMismatch(expected, found));
     }

     Ok(())
}

fn check_new_nonce_hash(expected_new_nonce: I256,
                        found_hash: i128::i128)
    -> error::Result<()>
{
    let mut expected_bytes = [0; 32];
    little_endian_i256_to_array(&mut expected_bytes, expected_new_nonce);
    let expected_sha1 = sha1_from_bytes(&[&expected_bytes])?;
    let expected_hash = little_endian_i128_from_array(array_ref!(expected_sha1, 4, 16));

    if expected_hash != found_hash {
        bail!(ErrorKind::NewNonceHashMismatch(expected_new_nonce, found_hash));
    }

    Ok(())
}

fn check_new_nonce_derived_hash(expected_new_nonce: I256,
                                marker: u8,
                                auth_key_aux_hash: [u8; 8],
                                found_hash: i128::i128)
    -> error::Result<()>
{
    let mut expected_bytes = [0; 32 + 1 + 8];  // TODO: replace magic numbers?

    {
        let (nonce_bytes, marker_byte, aux_hash_bytes) = mut_array_refs!(&mut expected_bytes, 32, 1, 8);
        little_endian_i256_to_array(nonce_bytes, expected_new_nonce);
        marker_byte[0] = marker;
        aux_hash_bytes.copy_from_slice(&auth_key_aux_hash);
    }

    let expected_sha1 = sha1_from_bytes(&[&expected_bytes])?;
    let expected_hash = little_endian_i128_from_array(array_ref!(expected_sha1, 4, 16));

    if expected_hash != found_hash {
        bail!(ErrorKind::NewNonceDerivedHashMismatch(
            expected_new_nonce, marker, auth_key_aux_hash, found_hash));
    }

    Ok(())
}

fn check_sha1(expected: &[u8], found: &[u8]) -> error::Result<()> {
    if expected != found {
        bail!(ErrorKind::Sha1Mismatch(expected.to_vec(), found.to_vec()));
    }

    Ok(())
}
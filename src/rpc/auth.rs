use std::fmt;

use byteorder::{BigEndian, ByteOrder, LittleEndian};
use chrono::Utc;
use futures::{self, Future, Poll};
use rand::{self, RngCore};
use serde_mtproto::{self, Boxed, MtProtoSized};

use ::bigint::calc_g_pows_bytes;
use ::crypto::{
    self,
    factor,
    hash::sha1_from_bytes,
    rsa::{self, RsaPublicKey},
};
use ::error::{self, ErrorKind};
use ::manual_types::i256::I256;
use ::network::{
    connection::Connection,
    state::{MessagePurpose, State},
};
use ::schema;
use ::utils::{
    little_endian_i128_from_array,
    little_endian_i128_into_array,
    little_endian_i256_into_array,
    little_endian_i256_to_array,
};


#[derive(Clone)]
pub struct AuthKey {
    pub(crate) raw: [u8; 256],
    aux_hash: i64,
    fingerprint: i64,
}

impl fmt::Debug for AuthKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("AuthKey")
            .field("raw", &&self.raw[..])
            .field("aux_hash", &self.aux_hash)
            .field("fingerprint", &self.fingerprint)
            .finish()
    }
}

impl PartialEq for AuthKey {
    fn eq(&self, other: &Self) -> bool {
        self.raw[..] == other.raw[..]
            && self.aux_hash == other.aux_hash
            && self.fingerprint == other.fingerprint
    }
}


pub struct AuthValues<C> {
    pub conn: C,
    pub state: State,
}

pub struct AuthFuture<C> {
    fut: Box<Future<Item = AuthValues<C>, Error = error::Error> + Send>,
}

impl<C: Connection> Future for AuthFuture<C> {
    type Item = AuthValues<C>;
    type Error = error::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        self.fut.poll()
    }
}


/// Combine all authorization steps defined below.
pub fn auth_with_state<C: Connection>(conn: C, state: State) -> AuthFuture<C> {
    let fut = futures::future::ok(Step1Input { conn, state })
        .and_then(auth_step1)
        .and_then(auth_step2)
        .and_then(auth_step3)
        .and_then(auth_step4);

    AuthFuture {
        fut: Box::new(fut),
    }
}

struct Step1Input<C> {
    conn: C,
    state: State,
}

/// Step 1: DH exchange initiation using PQ request
fn auth_step1<C: Connection>(input: Step1Input<C>)
    -> Box<Future<Item = Step2Input<C>, Error = error::Error> + Send>
{
    let nonce = rand::random();
    let req_pq = schema::rpc::req_pq { nonce };

    info!("Sending PQ request: {:#?}", req_pq);
    let request = input.conn.request_plain(input.state, req_pq, MessagePurpose::Content);

    Box::new(request.map(move |(conn, state, res_pq)| {
        Step2Input { conn, state, res_pq, nonce }
    }))
}

struct Step2Input<C> {
    conn: C,
    state: State,
    res_pq: schema::ResPQ,
    nonce: i128,
}

/// Step 2: Presenting PQ proof of work & server authentication
fn auth_step2<C: Connection>(input: Step2Input<C>)
    -> Box<Future<Item = Step3Input<C>, Error = error::Error> + Send>
{
    fn prepare_step2<C: Connection>(input: Step2Input<C>)
        -> error::Result<(C, State, schema::rpc::req_DH_params, i128, i128, I256)>
    {
        let Step2Input { conn, state, res_pq, nonce } = input;

        info!("Received PQ response: {:#?}", res_pq);

        check_nonce(nonce, res_pq.nonce)?;

        let pq_u64 = BigEndian::read_u64(&res_pq.pq);
        debug!("Decomposing pq = {}...", pq_u64);
        let (p_u32, q_u32) = factor::decompose_pq(pq_u64)?;
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
        let known_sha1_fingerprints = rsa::KNOWN_RAW_KEYS.iter()
            .map(|raw_key| {
                let sha1_fingerprint = RsaPublicKey::new(raw_key)?.sha1_fingerprint()?;
                Ok(sha1_fingerprint.iter().map(|b| format!("{:02x}", b)).collect::<String>())
            })
            .collect::<error::Result<Vec<_>>>()?;
        debug!("Known public key SHA1 fingerprints: {:?}", known_sha1_fingerprints);
        let known_fingerprints = rsa::KNOWN_RAW_KEYS.iter()
            .map(|raw_key| Ok(RsaPublicKey::new(raw_key)?.fingerprint()?))
            .collect::<error::Result<Vec<_>>>()?;
        debug!("Known public key fingerprints: {:?}", known_fingerprints);
        let server_pk_fingerprints = res_pq.server_public_key_fingerprints.inner().as_slice();
        debug!("Server public key fingerprints: {:?}", &server_pk_fingerprints);
        let (rsa_public_key, fingerprint) = rsa::find_first_key(server_pk_fingerprints)?;
        debug!("RSA public key used: {:#?}", &rsa_public_key);
        let encrypted_data = rsa_public_key.encrypt(&p_q_inner_data_serialized)?;
        debug!("Encrypted data: {:?}", encrypted_data.as_ref());

        let req_dh_params = schema::rpc::req_DH_params {
            nonce,
            server_nonce: res_pq.server_nonce,
            p: p.into(),
            q: q.into(),
            public_key_fingerprint: fingerprint,
            encrypted_data: encrypted_data.to_vec().into(),
        };

        Ok((conn, state, req_dh_params, nonce, res_pq.server_nonce, new_nonce))
    }

    let (conn, state, req_dh_params, nonce, server_nonce, new_nonce) = tryf!(prepare_step2(input));

    info!("Sending DH key exchange request: {:?}", req_dh_params);
    let request = conn.request_plain(state, req_dh_params, MessagePurpose::Content);

    Box::new(request.map(move |(conn, state, server_dh_params)| {
        Step3Input {
            conn,
            state,
            server_dh_params,
            nonce,
            server_nonce,
            new_nonce,
        }
    }))
}

struct Step3Input<C> {
    conn: C,
    state: State,
    server_dh_params: schema::Server_DH_Params,
    nonce: i128,
    server_nonce: i128,
    new_nonce: I256,
}

/// Step 3: DH key exchange complete
fn auth_step3<C: Connection>(input: Step3Input<C>)
    -> Box<Future<Item = Step4Input<C>, Error = error::Error> + Send>
{
    fn prepare_step3<C: Connection>(input: Step3Input<C>)
        -> error::Result<(C, State, schema::rpc::set_client_DH_params, i128, i128, I256, Vec<u8>, i32)>
    {
        let Step3Input { conn, state, server_dh_params, nonce, server_nonce, new_nonce } = input;

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

                let tmp_aes_params = crypto::aes::AesParams {
                    key: array_int! {
                        20 => &*hash1,
                        12 => &hash2[0..12],
                    },
                    iv: array_int! {
                        8  => &hash2[12..20],
                        20 => &*hash3,
                        4  => &new_nonce_bytes[0..4],
                    },
                };

                let server_dh_inner_decrypted = crypto::aes::aes_ige_decrypt(
                    &tmp_aes_params,
                    &server_dh_params_ok.encrypted_answer,
                );

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

                let (g_b, g_ab) = calc_g_pows_bytes(
                    server_dh_inner.g as u32,
                    &server_dh_inner.g_a,
                    &server_dh_inner.dh_prime,
                )?;

                let client_dh_inner = Boxed::new(schema::Client_DH_Inner_Data {
                    nonce,
                    server_nonce,
                    retry_id: 0,  // TODO: actual retry ID
                    g_b: g_b.into(),
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

                let encrypted_data = crypto::aes::aes_ige_encrypt(
                    &tmp_aes_params,
                    &client_dh_inner_to_encrypt,
                ).into();

                let set_client_dh_params = schema::rpc::set_client_DH_params {
                    nonce,
                    server_nonce,
                    encrypted_data,
                };

                let auth_key_bytes = g_ab;
                assert_eq!(auth_key_bytes.len(), 256);

                // Hopefully server will use 64-bit integers before Year 2038
                // Problem kicks in
                let local_timestamp = Utc::now().timestamp() as i32;
                let time_offset = server_dh_inner.server_time - local_timestamp;

                Ok((conn, state, set_client_dh_params, nonce, server_nonce, new_nonce, auth_key_bytes, time_offset))
            },
        }
    }

    let (conn, state, set_client_dh_params, nonce, server_nonce, new_nonce, auth_key_bytes, time_offset) =
        tryf!(prepare_step3(input));

    let request = conn.request_plain(state, set_client_dh_params, MessagePurpose::Content);

    Box::new(request.map(move |(conn, state, set_client_dh_params_answer)| {
        Step4Input {
            conn,
            state,
            set_client_dh_params_answer,
            nonce,
            server_nonce,
            new_nonce,
            auth_key_bytes,
            time_offset,
        }
    }))
}

struct Step4Input<C> {
    conn: C,
    state: State,
    set_client_dh_params_answer: schema::Set_client_DH_params_answer,
    nonce: i128,
    server_nonce: i128,
    new_nonce: I256,
    auth_key_bytes: Vec<u8>,
    time_offset: i32,
}

fn auth_step4<C: Connection>(input: Step4Input<C>)
    -> error::Result<AuthValues<C>>
{
    let Step4Input {
        conn,
        mut state,
        set_client_dh_params_answer,
        nonce,
        server_nonce,
        new_nonce,
        auth_key_bytes,
        time_offset,
    } = input;

    info!("Received server DH verification: {:#?}", set_client_dh_params_answer);

    let auth_key_sha1 = sha1_from_bytes(&[&auth_key_bytes])?;
    let auth_key = AuthKey {
        raw: array_int! { 256 => &auth_key_bytes },
        aux_hash: LittleEndian::read_i64(&auth_key_sha1[0..8]),
        fingerprint: LittleEndian::read_i64(&auth_key_sha1[8..16]),
    };

    match set_client_dh_params_answer {
        schema::Set_client_DH_params_answer::dh_gen_ok(dh_gen_ok) => {
            info!("DH params verification succeeded: {:?}", dh_gen_ok);

            check_nonce(nonce, dh_gen_ok.nonce)?;
            check_server_nonce(server_nonce, dh_gen_ok.server_nonce)?;
            check_new_nonce_derived_hash(new_nonce, 1, auth_key.aux_hash, dh_gen_ok.new_nonce_hash1)?;

            state.auth_key = Some(auth_key);
            state.time_offset = time_offset;

            Ok(AuthValues { conn, state })
        },
        schema::Set_client_DH_params_answer::dh_gen_retry(dh_gen_retry) => {
            info!("DH params verification needs a retry: {:?}", dh_gen_retry);

            check_nonce(nonce, dh_gen_retry.nonce)?;
            check_server_nonce(server_nonce, dh_gen_retry.server_nonce)?;
            check_new_nonce_derived_hash(new_nonce, 2, auth_key.aux_hash, dh_gen_retry.new_nonce_hash2)?;

            // TODO: implement DH retries
            unimplemented!();
        },
        schema::Set_client_DH_params_answer::dh_gen_fail(dh_gen_fail) => {
            error!("DH params verification failed: {:?}", dh_gen_fail);

            check_nonce(nonce, dh_gen_fail.nonce)?;
            check_server_nonce(server_nonce, dh_gen_fail.server_nonce)?;
            check_new_nonce_derived_hash(new_nonce, 3, auth_key.aux_hash, dh_gen_fail.new_nonce_hash3)?;

            bail!(ErrorKind::SetClientDHParamsAnswerFail);
        },
    }
}


// ===== UTILS ===== //

fn check_nonce(expected: i128, found: i128) -> error::Result<()> {
     if expected != found {
         bail!(ErrorKind::NonceMismatch(expected, found));
     }

     Ok(())
}

fn check_server_nonce(expected: i128, found: i128) -> error::Result<()> {
     if expected != found {
         bail!(ErrorKind::ServerNonceMismatch(expected, found));
     }

     Ok(())
}

fn check_new_nonce_hash(expected_new_nonce: I256,
                        found_hash: i128)
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
                                auth_key_aux_hash: i64,
                                found_hash: i128)
    -> error::Result<()>
{
    let mut expected_bytes = [0; 32 + 1 + 8];  // TODO: replace magic numbers?

    {
        let (nonce_bytes, marker_byte, aux_hash_bytes) = mut_array_refs!(&mut expected_bytes, 32, 1, 8);
        little_endian_i256_to_array(nonce_bytes, expected_new_nonce);
        marker_byte[0] = marker;
        LittleEndian::write_i64(aux_hash_bytes, auth_key_aux_hash);
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

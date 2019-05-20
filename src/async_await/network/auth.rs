use std::net::SocketAddr;
use std::time::Duration;

use arrayref::{array_ref, mut_array_refs};
use byteorder::{BigEndian, ByteOrder, LittleEndian};
use chrono::Utc;
use error_chain::bail;
use futures_util::compat::Future01CompatExt;
use log::{debug, error, info, warn};
use rand::{self, RngCore};
use serde_bytes::ByteBuf;
use serde_mtproto::{self, Boxed, MtProtoSized};

use crate::bigint::calc_g_pows_bytes;
use crate::crypto::{
    self,
    factor,
    hash::sha1_from_bytes,
    rsa::{self, RsaPublicKey},
};
use crate::error::{self, ErrorKind};
use crate::manual_types::i256::I256;
use crate::async_await::network::{
    connection::Connection,
};
use crate::network::auth::AuthKey;
use crate::network::state::State;
use crate::schema::{constructors, functions, types};
use crate::utils::{
    little_endian_i128_from_array,
    little_endian_i128_into_array,
    little_endian_i256_into_array,
    little_endian_i256_to_array,
};


/// Combine all authorization steps defined below.
pub async fn auth_with_state<C>(state: &mut State, conn: C) -> error::Result<()>
where
    C: Connection,
{
    let step1_input = Step1Input { state, conn };
    let step2_input = auth_step1(step1_input).await?;
    let step3_input = auth_step2(step2_input).await?;
    let step4_input = auth_step3(step3_input).await?;
    auth_step4(step4_input)?;

    Ok(())
}

pub async fn connect_auth_with_state<C>(
    state: &mut State,
    server_addr: SocketAddr,
) -> error::Result<()>
where
    C: Connection,
{
    let conn = C::connect(server_addr).await?;

    if state.auth_key.is_none() {
        auth_with_state(state, conn).await?;
    } else {
        warn!("User is already authenticated!");
        // FIXME: Return "already authenticated" error here?
    }

    Ok(())
}

pub async fn connect_auth_with_state_retryable<C>(
    state: &mut State,
    server_addr: SocketAddr,
    retries: usize,
    retry_delay_millis: u64,
) -> error::Result<()>
where
    C: Connection,
{
    for retry in 0..retries {
        match connect_auth_with_state::<C>(state, server_addr).await {
            Ok(()) => return Ok(()),
            // HACK: workaround for `error[E0277]: `(dyn std::error::Error + std::marker::Send +
            // 'static)` cannot be shared between threads safely`
            // `the trait `std::marker::Sync` is not implemented for `(dyn std::error::Error +
            // std::marker::Send + 'static)`
            Err(error) => match { let kind = error.kind(); kind } {
                // Only retry for connections that received a TCP packet with RST flag
                ErrorKind::ReceivedPacketWithRst => {
                    warn!("Performing retry #{} in {}ms...", retry + 1, retry_delay_millis);

                    let duration = Duration::from_millis(retry_delay_millis);

                    match tokio_timer::sleep(duration).compat().await {
                        Ok(()) => continue,
                        Err(e) => return Err(error.chain_err(|| ErrorKind::TokioTimer(e))),
                    }
                },
                // Other errors should be propagated
                _ => return Err(error),
            },
        }
    }

    connect_auth_with_state::<C>(state, server_addr).await?;

    Ok(())
}

struct Step1Input<'state, C> {
    state: &'state mut State,
    conn: C,
}

/// Step 1: DH exchange initiation using PQ request
async fn auth_step1<'state, C>(input: Step1Input<'state, C>) -> error::Result<Step2Input<'state, C>>
where
    C: Connection,
{
    let Step1Input { state, mut conn } = input;

    let nonce = rand::random();
    let req_pq = functions::req_pq { nonce };

    info!("Sending PQ request: {:#?}", req_pq);
    let res_pq = conn.request_plain(state, req_pq).await?;

    Ok(Step2Input { conn, state, res_pq, nonce })
}

struct Step2Input<'state, C> {
    conn: C,
    state: &'state mut State,
    res_pq: types::ResPQ,
    nonce: i128,
}

/// Step 2: Presenting PQ proof of work & server authentication
async fn auth_step2<'state, C>(input: Step2Input<'state, C>) -> error::Result<Step3Input<'state, C>>
where
    C: Connection,
{
    let Step2Input { mut conn, state, res_pq, nonce } = input;

    info!("Received PQ response: {:?}", res_pq);

    match res_pq {
        types::ResPQ::resPQ(res_pq) => {
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

            let p_q_inner_data = Boxed::new(types::P_Q_inner_data::p_q_inner_data(constructors::p_q_inner_data {
                pq: res_pq.pq.clone(),
                p: ByteBuf::from(p.clone()),
                q: ByteBuf::from(q.clone()),
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

            let req_dh_params = functions::req_DH_params {
                nonce,
                server_nonce: res_pq.server_nonce,
                p: ByteBuf::from(p),
                q: ByteBuf::from(q),
                public_key_fingerprint: fingerprint,
                encrypted_data: ByteBuf::from(encrypted_data.to_vec()),
            };

            let server_dh_params = conn.request_plain(state, req_dh_params).await?;

            Ok(Step3Input {
                conn,
                state,
                server_dh_params,
                nonce,
                server_nonce: res_pq.server_nonce,
                new_nonce,
            })
        },
    }
}

struct Step3Input<'state, C> {
    conn: C,
    state: &'state mut State,
    server_dh_params: types::Server_DH_Params,
    nonce: i128,
    server_nonce: i128,
    new_nonce: I256,
}

/// Step 3: DH key exchange complete
async fn auth_step3<'state, C>(input: Step3Input<'state, C>) -> error::Result<Step4Input<'state>>
where
    C: Connection,
{
    let Step3Input { mut conn, state, server_dh_params, nonce, server_nonce, new_nonce } = input;

    info!("Received server DH parameters: {:?}", server_dh_params);

    match server_dh_params {
        types::Server_DH_Params::server_DH_params_fail(server_dh_params_fail) => {
            error!("DH request failed: {:?}", server_dh_params_fail);

            check_nonce(nonce, server_dh_params_fail.nonce)?;
            check_server_nonce(server_nonce, server_dh_params_fail.server_nonce)?;
            check_new_nonce_hash(new_nonce, server_dh_params_fail.new_nonce_hash)?;

            bail!(ErrorKind::ServerDHParamsFail);
        },
        types::Server_DH_Params::server_DH_params_ok(server_dh_params_ok) => {
            info!("DH request succeeded: {:?}", server_dh_params_ok);

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
                serde_mtproto::from_bytes_reuse::<Boxed<types::Server_DH_inner_data>>(server_dh_inner_bytes, &["server_DH_inner_data"])?;

            let server_dh_inner_len = server_dh_inner_bytes.len() - random_tail.len();
            let server_dh_inner_client_hash =
                sha1_from_bytes(&[&server_dh_inner_bytes[0..server_dh_inner_len]])?;
            check_sha1(server_dh_inner_server_hash, &server_dh_inner_client_hash)?;

            match server_dh_inner.into_inner() {
                types::Server_DH_inner_data::server_DH_inner_data(server_dh_inner) => {
                    check_nonce(nonce, server_dh_inner.nonce)?;
                    check_server_nonce(server_nonce, server_dh_inner.server_nonce)?;

                    let (g_b, g_ab) = calc_g_pows_bytes(
                        server_dh_inner.g as u32,
                        &server_dh_inner.g_a,
                        &server_dh_inner.dh_prime,
                    )?;

                    let client_dh_inner = Boxed::new(types::Client_DH_Inner_Data::client_DH_inner_data(constructors::client_DH_inner_data {
                        nonce,
                        server_nonce,
                        retry_id: 0,  // TODO: actual retry ID
                        g_b: ByteBuf::from(g_b),
                    }));

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

                    let encrypted_data = ByteBuf::from(crypto::aes::aes_ige_encrypt(
                        &tmp_aes_params,
                        &client_dh_inner_to_encrypt,
                    ));

                    let set_client_dh_params = functions::set_client_DH_params {
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

                    let set_client_dh_params_answer = conn.request_plain(state, set_client_dh_params).await?;

                    Ok(Step4Input {
                        state,
                        set_client_dh_params_answer,
                        nonce,
                        server_nonce,
                        new_nonce,
                        auth_key_bytes,
                        time_offset,
                    })
                },
            }
        },
    }
}

struct Step4Input<'state> {
    state: &'state mut State,
    set_client_dh_params_answer: types::Set_client_DH_params_answer,
    nonce: i128,
    server_nonce: i128,
    new_nonce: I256,
    auth_key_bytes: Vec<u8>,
    time_offset: i32,
}

fn auth_step4<'state>(input: Step4Input<'state>) -> error::Result<()> {
    let Step4Input {
        state,
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
        types::Set_client_DH_params_answer::dh_gen_ok(dh_gen_ok) => {
            info!("DH params verification succeeded: {:?}", dh_gen_ok);

            check_nonce(nonce, dh_gen_ok.nonce)?;
            check_server_nonce(server_nonce, dh_gen_ok.server_nonce)?;
            check_new_nonce_derived_hash(new_nonce, 1, auth_key.aux_hash, dh_gen_ok.new_nonce_hash1)?;

            // This will drop the old auth key, if present
            state.auth_key = Some(auth_key);
            state.time_offset = time_offset;

            Ok(())
        },
        types::Set_client_DH_params_answer::dh_gen_retry(dh_gen_retry) => {
            warn!("DH params verification needs a retry: {:?}", dh_gen_retry);

            check_nonce(nonce, dh_gen_retry.nonce)?;
            check_server_nonce(server_nonce, dh_gen_retry.server_nonce)?;
            check_new_nonce_derived_hash(new_nonce, 2, auth_key.aux_hash, dh_gen_retry.new_nonce_hash2)?;

            // TODO: implement DH retries
            unimplemented!();
        },
        types::Set_client_DH_params_answer::dh_gen_fail(dh_gen_fail) => {
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
        bail!(ErrorKind::NewNonceHashMismatch(expected_new_nonce, expected_hash, found_hash));
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

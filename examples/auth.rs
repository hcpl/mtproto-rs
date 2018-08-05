extern crate byteorder;
extern crate chrono;
extern crate dotenv;
extern crate env_logger;
#[macro_use]
extern crate error_chain;
extern crate extprim;
extern crate futures;
extern crate hyper;
#[macro_use]
extern crate log;
extern crate mtproto;
extern crate openssl;
extern crate rand;
extern crate serde;
extern crate serde_mtproto;
extern crate tokio;


use byteorder::{BigEndian, ByteOrder, LittleEndian};
use chrono::Utc;
use extprim::i128;
use futures::{Future, Stream};
use mtproto::I256;
use mtproto::rpc::{AppInfo, MessageType, Session};
use mtproto::rpc::session::SessionConnection;
use mtproto::rpc::connection::ConnectionConfig;
use mtproto::rpc::encryption::asymm;
use mtproto::schema;
use openssl::{aes, bn, hash, symm};
use serde_mtproto::{Boxed, MtProtoSized};
use rand::Rng;


mod error {
    error_chain! {
        links {
            MtProto(::mtproto::Error, ::mtproto::ErrorKind);
            SerdeMtProto(::serde_mtproto::Error, ::serde_mtproto::ErrorKind);
        }

        foreign_links {
            Io(::std::io::Error);
            OpenSsl(::openssl::error::ErrorStack);
            SetLogger(::log::SetLoggerError);
        }

        errors {
            NonceMismatch(expected: ::extprim::i128::i128, found: ::extprim::i128::i128) {
                description("nonce mismatch")
                display("nonce mismatch (expected {}, found {})", expected, found)
            }

            ServerDHParamsFail {
                description("server didn't send DH parameters")
                display("server didn't send DH parameters")
            }

            SetClientDHParamsAnswerFail {
                description("server failed to verify DH parameters")
                display("server failed to verify DH parameters")
            }
        }
    }
}

use error::{ErrorKind, ResultExt};

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


macro_rules! unpack {
    ($func:ident ($($args:ident,)*)) => {
        |($($args,)*)| $func($($args),*)
    };

    ($func:ident ($($args:ident),*)) => {
        unpack!($func($($args,)*))
    };
}

/// Initializes session and combines all authorization steps defined below.
fn auth(conn_config: ConnectionConfig) -> Box<Future<Item = (), Error = error::Error> + Send> {
    let app_info = tryf!(fetch_app_info());

    let session = Session::new(rand::random(), app_info);
    let session_conn = session.connect(conn_config).map_err(Into::<error::Error>::into);

    let auth_future = session_conn
        .map(|sconn| (sconn,))
        .and_then(unpack!(auth_step1(session_conn)))
        .and_then(unpack!(auth_step2(session_conn, response, nonce)))
        .and_then(unpack!(auth_step3(session_conn, response, nonce, server_nonce, new_nonce)))
        .and_then(unpack!(auth_step4(session_conn, response, nonce, server_nonce, new_nonce, auth_key, time_offset)));

    Box::new(auth_future)
}


/// Step 1: DH exchange initiation using PQ request
fn auth_step1(session_conn: SessionConnection)
    -> Box<Future<Item = (
           SessionConnection,
           schema::ResPQ,
           i128::i128,
       ), Error = error::Error> + Send>
{
    let nonce = rand::random();
    let req_pq = schema::rpc::req_pq {
        nonce: nonce,
    };

    info!("Sending PQ request: {:#?}", req_pq);
    let request = session_conn.request(req_pq, MessageType::PlainText, MessageType::PlainText);

    Box::new(request.map(move |(session_conn, response)| {
        (session_conn, response, nonce)
    }).map_err(Into::into))
}

/// Step 2: Presenting PQ proof of work & server authentication
fn auth_step2(session: SessionConnection,
              res_pq: schema::ResPQ,
              nonce: i128::i128)
    -> Box<Future<Item = (
           SessionConnection,
           schema::Server_DH_Params,
           i128::i128,
           i128::i128,
           I256,
       ), Error = error::Error> + Send>
{
    info!("Received PQ response: {:#?}", res_pq);

    if nonce != res_pq.nonce {
        bailf!(ErrorKind::NonceMismatch(nonce, res_pq.nonce));
    }

    let pq_u64 = BigEndian::read_u64(&res_pq.pq);
    debug!("Decomposing pq = {}...", pq_u64);
    let (p_u32, q_u32) = tryf!(asymm::decompose_pq(pq_u64));
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

    let p_q_inner_data_serialized = tryf!(serde_mtproto::to_bytes(&p_q_inner_data));
    debug!("Data bytes to send: {:?}", &p_q_inner_data_serialized);
    let known_sha1_fingerprints = tryf!(asymm::KNOWN_RAW_KEYS.iter()
        .map(|raw_key| {
            let sha1_fingerprint = raw_key.read()?.sha1_fingerprint()?;
            Ok(sha1_fingerprint.iter().map(|b| format!("{:02x}", b)).collect::<String>())
        })
        .collect::<error::Result<Vec<_>>>());
    debug!("Known public key SHA1 fingerprints: {:?}", known_sha1_fingerprints);
    let known_fingerprints = tryf!(asymm::KNOWN_RAW_KEYS.iter()
        .map(|raw_key| Ok(raw_key.read()?.fingerprint()?))
        .collect::<error::Result<Vec<_>>>());
    debug!("Known public key fingerprints: {:?}", known_fingerprints);
    let server_pk_fingerprints = res_pq.server_public_key_fingerprints.inner().as_slice();
    debug!("Server public key fingerprints: {:?}", &server_pk_fingerprints);
    let (rsa_public_key, fingerprint) =
        tryf!(asymm::find_first_key_fail_safe(server_pk_fingerprints));
    debug!("RSA public key used: {:#?}", &rsa_public_key);
    let encrypted_data = tryf!(rsa_public_key.encrypt(&p_q_inner_data_serialized));
    debug!("Encrypted data: {:?}", encrypted_data.as_ref());
    let encrypted_data2 = tryf!(rsa_public_key.encrypt2(&p_q_inner_data_serialized));
    debug!("Encrypted data 2: {:?}", &encrypted_data2);

    let req_dh_params = schema::rpc::req_DH_params {
        nonce,
        server_nonce: res_pq.server_nonce,
        p: p.into(),
        q: q.into(),
        public_key_fingerprint: fingerprint,
        encrypted_data: encrypted_data.to_vec().into(),
        //encrypted_data: encrypted_data2.into(),
    };

    info!("Sending DH key exchange request: {:?}", req_dh_params);
    let request = session.request(req_dh_params, MessageType::PlainText, MessageType::PlainText);

    // These are necessary because using `res_pq.${field}` in the closuse itself will move `res_pq`
    // while having a borrow in `res_pq.server_public_key_fingerprints.inner().as_slice()`
    let nonce = res_pq.nonce;
    let server_nonce = res_pq.server_nonce;

    Box::new(request.map(move |(session_conn, response)| {
        (session_conn, response, nonce, server_nonce, new_nonce)
    }).map_err(Into::into))
}

/// Step 3: DH key exchange complete
fn auth_step3(session: SessionConnection,
              server_dh_params: schema::Server_DH_Params,
              nonce: i128::i128,
              server_nonce: i128::i128,
              new_nonce: I256)
    -> Box<Future<Item = (
           SessionConnection,
           schema::Set_client_DH_params_answer,
           i128::i128,
           i128::i128,
           I256,
           Vec<u8>,
           i32,
       ), Error = error::Error> + Send>
{
    info!("Received server DH parameters: {:#?}", server_dh_params);

    match server_dh_params {
        schema::Server_DH_Params::server_DH_params_fail(server_dh_params_fail) => {
            error!("DH request failed: {:?}", server_dh_params_fail);

            Box::new(futures::future::err(ErrorKind::ServerDHParamsFail.into()))
        },
        schema::Server_DH_Params::server_DH_params_ok(server_dh_params_ok) => {
            let server_nonce_bytes = little_endian_i128_to_bytes(server_nonce);
            let new_nonce_bytes = little_endian_i256_to_bytes(new_nonce);

            let hash1 = tryf!(sha1_from_bytes(&[&new_nonce_bytes, &server_nonce_bytes]));
            let hash2 = tryf!(sha1_from_bytes(&[&server_nonce_bytes, &new_nonce_bytes]));
            let hash3 = tryf!(sha1_from_bytes(&[&new_nonce_bytes, &new_nonce_bytes]));

            let mut tmp_aes_key = [0; 32];
            tmp_aes_key[0..20].copy_from_slice(&*hash1);
            tmp_aes_key[20..32].copy_from_slice(&hash2[0..12]);
            let mut tmp_aes_iv = [0; 32];
            tmp_aes_iv[0..8].copy_from_slice(&hash2[12..20]);
            tmp_aes_iv[8..28].copy_from_slice(&*hash3);
            tmp_aes_iv[28..32].copy_from_slice(&new_nonce_bytes[0..4]);

            // Key is 256-bit => can unwrap safely
            let aes_decrypt_key = aes::AesKey::new_decrypt(&tmp_aes_key).unwrap();
            let mut decrypted_answer = vec![0; server_dh_params_ok.encrypted_answer.len()];
            aes::aes_ige(server_dh_params_ok.encrypted_answer.as_ref(), decrypted_answer.as_mut_slice(), &aes_decrypt_key, &mut tmp_aes_iv.clone(), symm::Mode::Decrypt);

            const SHA1_HASH_LENGTH: usize = 20;
            let (answer_server_hash, answer_bytes) = decrypted_answer.split_at(SHA1_HASH_LENGTH);
            let (answer, random_tail) = tryf!(serde_mtproto::from_bytes_reuse::<Boxed<schema::Server_DH_inner_data>>(answer_bytes, &[]));
            let answer_len = answer_bytes.len() - random_tail.len();
            let answer_client_hash = tryf!(sha1_from_bytes(&[&answer_bytes[0..answer_len]]));
            assert_eq!(answer_server_hash, answer_client_hash.as_ref());

            let g = tryf!(bn::BigNum::from_u32(answer.inner().g as u32));
            let mut b = tryf!(bn::BigNum::new());
            tryf!(b.rand(2048, bn::MsbOption::ONE, true));
            let dh_prime = tryf!(bn::BigNum::from_slice(&*answer.inner().dh_prime));
            let mut g_b = tryf!(bn::BigNum::new());
            let mut ctx = tryf!(bn::BigNumContext::new());
            tryf!(g_b.mod_exp(&g, &b, &dh_prime, &mut ctx));

            let client_dh_inner_data = Boxed::new(schema::Client_DH_Inner_Data {
                nonce,
                server_nonce,
                retry_id: 0,  // TODO: actual retry ID
                g_b: g_b.to_vec().into(),
            });

            let client_dh_inner_data_len = tryf!(client_dh_inner_data.size_hint());
            let random_tail_len = (16 - ((SHA1_HASH_LENGTH + client_dh_inner_data_len) % 16)) % 16;
            let mut client_dh_inner_data_to_encrypt =
                vec![0; SHA1_HASH_LENGTH + client_dh_inner_data_len + random_tail_len];

            {
                let (client_dh_inner_data_hash, client_dh_inner_data_rest) =
                    client_dh_inner_data_to_encrypt.split_at_mut(SHA1_HASH_LENGTH);
                let (client_dh_inner_data_bytes, random_tail) =
                    client_dh_inner_data_rest.split_at_mut(client_dh_inner_data_len);
                tryf!(serde_mtproto::to_writer(&mut *client_dh_inner_data_bytes, &client_dh_inner_data));
                let hash_bytes = tryf!(sha1_from_bytes(&[client_dh_inner_data_bytes]));
                client_dh_inner_data_hash.copy_from_slice(&*hash_bytes);
                rand::thread_rng().fill_bytes(random_tail);
            }

            // Key is 256-bit => can unwrap safely
            let aes_encrypt_key = aes::AesKey::new_encrypt(&tmp_aes_key).unwrap();
            let mut encrypted_data = vec![0; client_dh_inner_data_to_encrypt.len()];
            aes::aes_ige(&client_dh_inner_data_to_encrypt, encrypted_data.as_mut_slice(), &aes_encrypt_key, &mut tmp_aes_iv.clone(), symm::Mode::Encrypt);

            let set_client_dh_params = schema::rpc::set_client_DH_params {
                nonce,
                server_nonce,
                encrypted_data: encrypted_data.into(),
            };

            let request = session.request(set_client_dh_params, MessageType::PlainText, MessageType::PlainText);

            let g_a = tryf!(bn::BigNum::from_slice(&*answer.inner().g_a));
            let mut g_ab = tryf!(bn::BigNum::new());
            tryf!(g_ab.mod_exp(&g_a, &b, &dh_prime, &mut ctx));
            let auth_key = g_ab.to_vec();

            // Hopefully server will use 64-bit integers before Year 2038
            // Problem kicks in
            let local_timestamp = Utc::now().timestamp() as i32;
            let time_offset = answer.inner().server_time - local_timestamp;

            Box::new(request.map(move |(session_conn, response)| {
                (
                    session_conn, response, nonce, server_nonce, new_nonce,
                    auth_key, time_offset,
                )
            }).map_err(Into::into))
        },
    }
}

fn auth_step4(_session: SessionConnection,
              set_client_dh_params_answer: schema::Set_client_DH_params_answer,
              _nonce: i128::i128,
              _server_nonce: i128::i128,
              _new_nonce: I256,
              auth_key: Vec<u8>,
              _time_offset: i32)
    -> Box<Future<Item = (), Error = error::Error> + Send>
{
    info!("Received server DH verification: {:#?}", set_client_dh_params_answer);

    let auth_key_sha1 = tryf!(sha1_from_bytes(&[&auth_key]));
    let mut auth_key_hash = [0; 8];
    auth_key_hash.copy_from_slice(&auth_key_sha1[0..8]);
    let mut auth_key_aux_hash = [0; 8];
    auth_key_aux_hash.copy_from_slice(&auth_key_sha1[12..20]);

    match set_client_dh_params_answer {
        schema::Set_client_DH_params_answer::dh_gen_ok(dh_gen_ok) => {
            info!("DH params verification succeeded: {:?}", dh_gen_ok);

            Box::new(futures::future::ok(()))
        },
        schema::Set_client_DH_params_answer::dh_gen_retry(dh_gen_retry) => {
            info!("DH params verification needs a retry: {:?}", dh_gen_retry);

            unimplemented!();
        },
        schema::Set_client_DH_params_answer::dh_gen_fail(dh_gen_fail) => {
            error!("DH params verification failed: {:?}", dh_gen_fail);

            Box::new(futures::future::err(ErrorKind::SetClientDHParamsAnswerFail.into()))
        },
    }
}


/// Obtain `AppInfo` from all possible known sources in the following
/// priority:
///
/// * Environment variables `MTPROTO_API_ID` and `MTPROTO_API_HASH`;
/// * `AppInfo.toml` file with `api_id` and `api_hash` fields.
fn fetch_app_info() -> error::Result<AppInfo> {
    AppInfo::from_env().or_else(|from_env_err| {
        AppInfo::from_toml_file("AppInfo.toml").map_err(|read_toml_err| {
            from_env_err.chain_err(|| read_toml_err)
        })
    }).chain_err(|| {
        "this example needs either both `MTPROTO_API_ID` and `MTPROTO_API_HASH` environment \
         variables set, or an AppInfo.toml file with `api_id` and `api_hash` fields in it"
    })
}

fn little_endian_i128_to_bytes(n: i128::i128) -> [u8; 16] {
    let mut buf = [0; 16];
    LittleEndian::write_u64(&mut buf[0..8], n.low64());
    LittleEndian::write_i64(&mut buf[8..16], n.high64());
    buf
}

fn little_endian_i256_to_bytes(n: I256) -> [u8; 32] {
    let mut buf = [0; 32];
    LittleEndian::write_u64(&mut buf[0..8], n.low128().low64());
    LittleEndian::write_u64(&mut buf[8..16], n.low128().high64());
    LittleEndian::write_u64(&mut buf[16..24], n.high128().low64());
    LittleEndian::write_i64(&mut buf[24..32], n.high128().high64());
    buf
}

fn sha1_from_bytes(bytes: &[&[u8]]) -> error::Result<hash::DigestBytes> {
    let mut hasher = hash::Hasher::new(hash::MessageDigest::sha1())?;
    for b in bytes {
        hasher.update(b)?;
    }
    hasher.finish().map_err(Into::into)
}


fn processed_auth(config: ConnectionConfig, tag: &'static str)
    -> Box<Future<Item = (), Error = ()> + Send>
{
    Box::new(auth(config).then(move |res| {
        match res {
            Ok(()) => println!("Success ({})", tag),
            Err(e) => println!("{} ({})", e, tag),
        }

        Ok(())
    }))
}

fn main() {
    env_logger::init();
    dotenv::dotenv().ok();  // Fail silently if no .env is present

    tokio::run(futures::stream::futures_unordered(vec![
        processed_auth(ConnectionConfig::tcp_abridged_with_default_config(), "tcp-abridged"),
        processed_auth(ConnectionConfig::tcp_intermediate_with_default_config(), "tcp-intermediate"),
        processed_auth(ConnectionConfig::tcp_full_with_default_config(), "tcp-full"),
        processed_auth(ConnectionConfig::http_with_default_config(), "http"),
    ]).for_each(|_| Ok(())));
}

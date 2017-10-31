extern crate byteorder;
extern crate dotenv;
extern crate env_logger;
#[macro_use]
extern crate error_chain;
extern crate extprim;
extern crate futures;
#[macro_use]
extern crate log;
extern crate mtproto;
extern crate rand;
extern crate serde;
extern crate serde_mtproto;
extern crate tokio_core;
extern crate tokio_io;


use std::fmt;

use byteorder::{BigEndian, ByteOrder, LittleEndian};
use extprim::i128;
use futures::Future;
use mtproto::tl::dynamic::TLObject;
use mtproto::rpc::{AppInfo, Message, MessageType, Session};
use mtproto::rpc::connection::{TCP_SERVER_ADDRS, TcpConnection, TcpMode};
use mtproto::rpc::encryption::asymm;
use mtproto::schema;
use rand::{Rng, ThreadRng};
use serde::de::DeserializeOwned;
use tokio_core::net::TcpStream;
use tokio_core::reactor::{Core, Handle};


mod error {
    error_chain! {
        links {
            MtProto(::mtproto::Error, ::mtproto::ErrorKind);
            SerdeMtProto(::serde_mtproto::Error, ::serde_mtproto::ErrorKind);
        }

        foreign_links {
            Io(::std::io::Error);
            SetLogger(::log::SetLoggerError);
        }

        errors {
            NonceMismatch(expected: ::extprim::i128::i128, found: ::extprim::i128::i128) {
                description("nonce mismatch")
                display("nonce mismatch (expected {}, found {})", expected, found)
            }

            ErrorCode(code: i32) {
                description("RPC returned an error code")
                display("RPC returned a {} error code", code)
            }

            BadMessage(found_len: usize) {
                description("Message length is neither 4, nor >= 24 bytes")
                display("Message length is neither 4, nor >= 24 bytes: {}", found_len)
            }

            ErrorsCollection(errors: Vec<Error>) {
                description("Collection of errors of this type")
                display("Collection of errors of this type: {:?}", errors)
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


fn auth(handle: Handle, tcp_mode: TcpMode) -> Box<Future<Item = (), Error = error::Error>> {
    let app_info = tryf!(fetch_app_info());

    let remote_addr = TCP_SERVER_ADDRS[0];
    let mut conn = TcpConnection::new(tcp_mode, remote_addr);
    let socket = TcpStream::connect(&remote_addr, &handle).map_err(error::Error::from);

    let auth_future = socket.and_then(|socket|
        -> Box<Future<Item = (TcpStream, Vec<u8>, Session, ThreadRng, TcpConnection, i128::i128), Error = error::Error>>
    {
        let mut rng = rand::thread_rng();
        let mut session = Session::new(rng.gen(), app_info);

        let nonce = rng.gen();
        let req_pq = schema::rpc::req_pq {
            nonce: nonce,
        };

        let message = tryf!(create_message(&mut session, req_pq, MessageType::PlainText));
        let request = conn.request(socket, message);

        Box::new(request.map(move |(s, b)| (s, b, session, rng, conn, nonce)).map_err(Into::into))
    }).and_then(|(socket, response_bytes, mut session, mut rng, mut conn, nonce)|
        -> Box<Future<Item = (TcpStream, Vec<u8>, Session, ThreadRng, TcpConnection), Error = error::Error>>
    {
        let response: Message<schema::ResPQ> =
            tryf!(parse_response(&session, &response_bytes, MessageType::PlainText));

        let res_pq = response.unwrap_plain_text_body();

        if nonce != res_pq.nonce {
            bailf!(ErrorKind::NonceMismatch(nonce, res_pq.nonce));
        }

        let pq_u64 = BigEndian::read_u64(&res_pq.pq);
        info!("Decomposing pq = {}...", pq_u64);
        let (p_u32, q_u32) = tryf!(asymm::decompose_pq(pq_u64));
        info!("Decomposed p = {}, q = {}", p_u32, q_u32);
        let u32_to_vec = |num| {
            let mut v = vec![0; 4];
            BigEndian::write_u32(v.as_mut_slice(), num);
            v
        };
        let p = u32_to_vec(p_u32);
        let q = u32_to_vec(q_u32);

        let p_q_inner_data = schema::P_Q_inner_data::p_q_inner_data(schema::p_q_inner_data {
            pq:  res_pq.pq,
            p: p.clone().into(),
            q: q.clone().into(),
            nonce: res_pq.nonce,
            server_nonce: res_pq.server_nonce,
            new_nonce: rng.gen(),
        });

        info!("Data to send: {:#?}", &p_q_inner_data);
        let p_q_inner_data_serialized = tryf!(serde_mtproto::to_bytes(&p_q_inner_data));
        info!("Data bytes to send: {:?}", &p_q_inner_data_serialized);
        let known_sha1_fingerprints = tryf!(asymm::KNOWN_RAW_KEYS.iter()
            .map(|raw_key| {
                let sha1_fingerprint = raw_key.read()?.sha1_fingerprint()?;
                Ok(sha1_fingerprint.iter().map(|b| format!("{:02x}", b)).collect::<String>())
            })
            .collect::<error::Result<Vec<_>>>());
        info!("Known public key SHA1 fingerprints: {:?}", known_sha1_fingerprints);
        let known_fingerprints = tryf!(asymm::KNOWN_RAW_KEYS.iter()
            .map(|raw_key| Ok(raw_key.read()?.fingerprint()?))
            .collect::<error::Result<Vec<_>>>());
        info!("Known public key fingerprints: {:?}", known_fingerprints);
        let server_pk_fingerprints = res_pq.server_public_key_fingerprints.inner().as_slice();
        info!("Server public key fingerprints: {:?}", &server_pk_fingerprints);
        let (rsa_public_key, fingerprint) =
            tryf!(asymm::find_first_key_fail_safe(server_pk_fingerprints));
        info!("RSA public key used: {:#?}", &rsa_public_key);
        let encrypted_data = tryf!(rsa_public_key.encrypt(&p_q_inner_data_serialized));
        info!("Encrypted data: {:?}", encrypted_data.as_ref());
        let encrypted_data2 = tryf!(rsa_public_key.encrypt2(&p_q_inner_data_serialized));
        info!("Encrypted data 2: {:?}", &encrypted_data2);

        let req_dh_params = schema::rpc::req_DH_params {
            nonce: res_pq.nonce,
            server_nonce: res_pq.server_nonce,
            p: p.into(),
            q: q.into(),
            public_key_fingerprint: fingerprint,
            encrypted_data: encrypted_data.to_vec().into(),
        };

        let message = tryf!(create_message(&mut session, req_dh_params, MessageType::PlainText));
        let request = conn.request(socket, message);

        Box::new(request.map(move |(s, b)| (s, b, session, rng, conn)).map_err(Into::into))
    }).and_then(|(_socket, response_bytes, session, _rng, _conn)| {
        let _: Message<schema::Server_DH_Params> =
            tryf!(parse_response(&session, &response_bytes, MessageType::PlainText));

        Box::new(futures::future::ok(()))
    });

    Box::new(auth_future)
}

/// Obtain `AppInfo` from all possible known sources in the following
/// priority:
///
/// * Environment variables `MTPROTO_API_ID` and `MTPROTO_API_HASH`;
/// * `AppInfo.toml` file with `api_id` and `api_hash` fields.
fn fetch_app_info() -> error::Result<AppInfo> {
    AppInfo::from_env().or_else(|from_env_err| {
        AppInfo::read_from_toml_file("AppInfo.toml").map_err(|read_toml_err| {
            from_env_err.chain_err(|| read_toml_err)
        })
    }).chain_err(|| {
        "this example needs either both `MTPROTO_API_ID` and `MTPROTO_API_HASH` environment \
         variables set, or an AppInfo.toml file with `api_id` and `api_hash` fields in it"
    })
}

fn create_message<T>(session: &mut Session,
                     data: T,
                     message_type: MessageType)
                    -> error::Result<Message<T>>
    where T: fmt::Debug + TLObject
{
    let message = match message_type {
        MessageType::PlainText => session.create_plain_text_message(data)?,
        MessageType::Encrypted => session.create_encrypted_message_no_acks(data)?.unwrap(),
    };
    info!("Message to send: {:#?}", &message);

    Ok(message)
}

fn parse_response<T>(session: &Session,
                     response_bytes: &[u8],
                     message_type: MessageType)
                    -> error::Result<Message<T>>
    where T: fmt::Debug + DeserializeOwned
{
    info!("Response bytes: {:?}", &response_bytes);

    let len = response_bytes.len();

    if len == 4 { // Must be an error code
        // Error codes are represented as negative i32
        let code = LittleEndian::read_i32(response_bytes);
        bail!(ErrorKind::ErrorCode(-code));
    } else if len < 24 {
        bail!(ErrorKind::BadMessage(len));
    }

    let encrypted_data_len = match message_type {
        MessageType::PlainText => None,
        MessageType::Encrypted => Some((len - 24) as u32),
    };

    let response = session.process_message(&response_bytes, encrypted_data_len)?;
    info!("Message received: {:#?}", &response);

    Ok(response)
}


fn run_collect_errors(core: &mut Core, tcp_modes: &[TcpMode]) -> Result<(), Vec<error::Error>> {
    let mut errors = vec![];

    for tcp_mode in tcp_modes {
        let auth_future = auth(core.handle(), *tcp_mode);

        if let Err(e) = core.run(auth_future) {
            errors.push(e);
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn run() -> error::Result<()> {
    env_logger::init()?;
    dotenv::dotenv().ok();  // Fail silently if no .env is present
    let mut core = Core::new()?;

    run_collect_errors(&mut core, &[
        TcpMode::Abridged,
        TcpMode::Intermediate,
        TcpMode::Full,
    ]).map_err(ErrorKind::ErrorsCollection)?;

    Ok(())
}

quick_main!(run);

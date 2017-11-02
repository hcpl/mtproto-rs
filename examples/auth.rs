extern crate byteorder;
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
extern crate rand;
extern crate serde;
extern crate serde_mtproto;
extern crate tokio_core;
extern crate void;


use byteorder::{BigEndian, ByteOrder};
use extprim::i128;
use futures::{Future, Stream};
use mtproto::rpc::{AppInfo, MessageType, Session};
use mtproto::rpc::session::SessionConnection;
use mtproto::rpc::connection::{HTTP_SERVER_ADDRS, TCP_SERVER_ADDRS, ConnectionConfig, TcpMode};
use mtproto::rpc::encryption::asymm;
use mtproto::schema;
use rand::{Rng, ThreadRng};
use tokio_core::reactor::{Core, Handle};
use void::Void;


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
    ($auth_step:ident ($($tt:tt),*)) => {
        |($($tt),*)| $auth_step($($tt),*)
    }
}

/// Initializes session and combines all authorization steps defined below.
fn auth(handle: Handle, conn_config: ConnectionConfig) -> Box<Future<Item = (), Error = error::Error>> {
    let app_info = tryf!(fetch_app_info());
    let mut rng = rand::thread_rng();

    let session = Session::new(rng.gen(), app_info);
    let session_conn = session.connect(handle, conn_config).map_err(Into::<error::Error>::into);

    let auth_future = session_conn
        .map(|sconn| (sconn, rng))
        .and_then(unpack!(auth_step1(session_conn, rng)))
        .and_then(unpack!(auth_step2(session_conn, response, rng, nonce)))
        .and_then(unpack!(auth_step3(session_conn, response, rng)));

    Box::new(auth_future)
}


/// Step 1: DH exchange initiation using PQ request
fn auth_step1(session_conn: SessionConnection,
              mut rng: ThreadRng)
    -> Box<Future<Item = (
           SessionConnection,
           schema::ResPQ,
           ThreadRng,
           i128::i128,
       ), Error = error::Error>>
{
    let nonce = rng.gen();
    let req_pq = schema::rpc::req_pq {
        nonce: nonce,
    };

    info!("Sending PQ request: {:#?}", req_pq);
    let request = session_conn.request(req_pq, MessageType::PlainText, MessageType::PlainText);

    Box::new(request.map(move |(session_conn, response)| {
        (session_conn, response, rng, nonce)
    }).map_err(Into::into))
}

/// Step 2: Presenting PQ proof of work & server authentication
fn auth_step2(session: SessionConnection,
              res_pq: schema::ResPQ,
              mut rng: ThreadRng,
              nonce: i128::i128)
    -> Box<Future<Item = (
           SessionConnection,
           schema::Server_DH_Params,
           ThreadRng,
       ), Error = error::Error>>
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

    let p_q_inner_data = schema::P_Q_inner_data::p_q_inner_data(schema::p_q_inner_data {
        pq: res_pq.pq,
        p: p.clone().into(),
        q: q.clone().into(),
        nonce: res_pq.nonce,
        server_nonce: res_pq.server_nonce,
        new_nonce: rng.gen(),
    });
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
        nonce: res_pq.nonce,
        server_nonce: res_pq.server_nonce,
        p: p.into(),
        q: q.into(),
        public_key_fingerprint: fingerprint,
        encrypted_data: encrypted_data.to_vec().into(),
        //encrypted_data: encrypted_data2.into(),
    };

    info!("Sending DH key exchange request: {:?}", req_dh_params);
    let request = session.request(req_dh_params, MessageType::PlainText, MessageType::PlainText);

    Box::new(request.map(move |(session, response)| {
        (session, response, rng)
    }).map_err(Into::into))
}

/// Step 3: DH key exchange complete
/// 
/// Should be this but step 2 in this implementation always ends with
/// 404 Not Found, so this is left empty for investigations.
fn auth_step3(_session: SessionConnection,
              server_dh_params: schema::Server_DH_Params,
              _rng: ThreadRng)
    -> Box<Future<Item = (), Error = error::Error>>
{
    info!("Received server DH parameters: {:#?}", server_dh_params);

    Box::new(futures::future::ok(()))
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


fn all_auths(core: &Core) -> Box<Future<Item = (), Error = Void>> {
    let mut futures: Vec<Box<Future<Item = (), Error = Void>>> = vec![];

    macro_rules! add_auth_future {
        ($($tt:tt)+) => {
            let auth_future = auth(core.handle(), $($tt)+).map(|_| $($tt)+).map_err(|e| ($($tt)+, e));
            let processed_auth_future = auth_future.then(|result| {
                let conn_type_text = |conn_config| match conn_config {
                    ConnectionConfig::Tcp(TcpMode::Abridged, _) => "tcp-abridged",
                    ConnectionConfig::Tcp(TcpMode::Intermediate, _) => "tcp-intermediate",
                    ConnectionConfig::Tcp(TcpMode::Full, _) => "tcp-full",
                    ConnectionConfig::Http(_) => "http",
                };

                match result {
                    Ok(conn_config) => println!("Success ({})", conn_type_text(conn_config)),
                    Err((conn_config, e)) => println!("{} ({})", e, conn_type_text(conn_config)),
                }

                Ok(())
            });

            futures.push(Box::new(processed_auth_future))
        };
    }

    add_auth_future!(ConnectionConfig::Tcp(TcpMode::Abridged,     TCP_SERVER_ADDRS[0]));
    add_auth_future!(ConnectionConfig::Tcp(TcpMode::Intermediate, TCP_SERVER_ADDRS[0]));
    add_auth_future!(ConnectionConfig::Tcp(TcpMode::Full,         TCP_SERVER_ADDRS[0]));
    add_auth_future!(ConnectionConfig::Http(HTTP_SERVER_ADDRS[0].clone()));

    Box::new(futures::stream::futures_unordered(futures).for_each(|_| Ok(())))
}

fn run() -> error::Result<()> {
    env_logger::init()?;
    dotenv::dotenv().ok();  // Fail silently if no .env is present
    let mut core = Core::new()?;

    let all_auths_future = all_auths(&core);
    core.run(all_auths_future).unwrap();  // The error is void

    Ok(())
}

quick_main!(run);
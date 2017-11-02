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


use byteorder::{BigEndian, ByteOrder};
use extprim::i128;
use futures::Future;
use mtproto::rpc::{AppInfo, MessageType, Session};
use mtproto::rpc::connection::{HTTP_SERVER_ADDRS, TCP_SERVER_ADDRS,
                               Connection, HttpConnection, TcpConnection, TcpMode};
use mtproto::rpc::encryption::asymm;
use mtproto::schema;
use rand::{Rng, ThreadRng};
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

fn tcp_auth(handle: Handle, tcp_mode: TcpMode) -> Box<Future<Item = (), Error = error::Error>> {
    let app_info = tryf!(fetch_app_info());
    let mut rng = rand::thread_rng();
    let session = Session::new(rng.gen(), app_info);

    let remote_addr = TCP_SERVER_ADDRS[0];
    // TODO: replace with session::connect
    let conn = TcpConnection::new(handle, tcp_mode, remote_addr)
        .map(|tcp_conn| Connection::Tcp(tcp_conn))
        .map_err(Into::into);

    let auth_future = conn
        .map(|conn| (conn, session, rng))
        .and_then(unpack!(auth_step1(conn, session, rng)))
        .and_then(unpack!(auth_step2(conn, response, session, rng, nonce)))
        .and_then(unpack!(auth_step3(conn, response, session, rng)));

    Box::new(auth_future)
}

fn http_auth(handle: Handle) -> Box<Future<Item = (), Error = error::Error>> {
    let app_info = tryf!(fetch_app_info());
    let mut rng = rand::thread_rng();
    let session = Session::new(rng.gen(), app_info);

    let remote_addr = HTTP_SERVER_ADDRS[0].clone();
    // TODO: replace with session::connect
    let http_conn = HttpConnection::new(handle, remote_addr);
    let conn = Connection::Http(http_conn);

    let auth_future = auth_step1(conn, session, rng)
        .and_then(unpack!(auth_step2(conn, response, session, rng, nonce)))
        .and_then(unpack!(auth_step3(conn, response, session, rng)));

    Box::new(auth_future)
}


fn auth_step1(conn: Connection,
              session: Session,
              mut rng: ThreadRng)
    -> Box<Future<Item = (
           Connection,
           schema::ResPQ,
           Session,
           ThreadRng,
           i128::i128,
       ), Error = error::Error>>
{
    let nonce = rng.gen();
    let req_pq = schema::rpc::req_pq {
        nonce: nonce,
    };

    let request = conn.request(session, req_pq, MessageType::PlainText, MessageType::PlainText);

    Box::new(request.map(move |(conn, response, session)| {
        (conn, response.unwrap(), session, rng, nonce)
    }).map_err(Into::into))
}

fn auth_step2(conn: Connection,
              response: schema::ResPQ,
              session: Session,
              mut rng: ThreadRng,
              nonce: i128::i128)
    -> Box<Future<Item = (
           Connection,
           schema::Server_DH_Params,
           Session,
           ThreadRng,
       ), Error = error::Error>>
{
    let res_pq = response;

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
        pq: res_pq.pq,
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
        //encrypted_data: encrypted_data2.into(),
    };

    let request = conn.request(session, req_dh_params, MessageType::PlainText, MessageType::PlainText);

    Box::new(request.map(move |(conn, response, session)| {
        (conn, response.unwrap(), session, rng)
    }).map_err(Into::into))
}

fn auth_step3(_conn: Connection,
              _response: schema::Server_DH_Params,
              _session: Session,
              _rng: ThreadRng)
    -> Box<Future<Item = (), Error = error::Error>>
{
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


fn run_collect_errors(core: &mut Core) -> Vec<error::Error> {
    let mut errors = vec![];

    macro_rules! run_auth_future {
        ($($tt:tt)+) => {
            let auth_future = $($tt)+;

            if let Err(e) = core.run(auth_future) {
                errors.push(e);
            }
        };
    }

    run_auth_future!(tcp_auth(core.handle(), TcpMode::Abridged));
    run_auth_future!(tcp_auth(core.handle(), TcpMode::Intermediate));
    run_auth_future!(tcp_auth(core.handle(), TcpMode::Full));
    run_auth_future!(http_auth(core.handle()));

    errors
}

fn run() -> error::Result<()> {
    env_logger::init()?;
    dotenv::dotenv().ok();  // Fail silently if no .env is present
    let mut core = Core::new()?;

    for (i, e) in run_collect_errors(&mut core).into_iter().enumerate() {
        println!("{}. {}", i + 1, e);
    }

    Ok(())
}

quick_main!(run);

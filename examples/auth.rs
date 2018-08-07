extern crate dotenv;
extern crate env_logger;
#[macro_use]
extern crate error_chain;
extern crate futures;
extern crate mtproto;
extern crate rand;
extern crate tokio;


use futures::{Future, Stream};
use mtproto::rpc::{AppInfo, Session};
use mtproto::rpc::auth::AuthValues;
use mtproto::rpc::connection::ConnectionConfig;


mod error {
    error_chain! {
        links {
            MtProto(::mtproto::Error, ::mtproto::ErrorKind);
        }
    }
}

use error::ResultExt;


/// Initialize session and execute authorization.
fn processed_auth(config: ConnectionConfig, tag: &'static str)
    -> Box<Future<Item = (), Error = ()> + Send>
{
    Box::new(futures::future::result(fetch_app_info()).and_then(|app_info| {
        let session = Session::new(rand::random(), app_info);
        mtproto::rpc::auth::auth_with_session(config, session).map_err(Into::into)
    }).then(move |res| {
        match res {
            Ok(AuthValues { auth_key, time_offset }) => {
                println!("Success ({}): auth key = {:?}, time offset = {}",
                    tag, auth_key, time_offset);
            },
            Err(e) => println!("{} ({})", e, tag),
        }

        Ok(())
    }))
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

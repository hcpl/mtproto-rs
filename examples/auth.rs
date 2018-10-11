extern crate dotenv;
extern crate env_logger;
#[macro_use]
extern crate error_chain;
extern crate futures;
extern crate mtproto;
extern crate rand;
extern crate tokio;

#[macro_use]
extern crate log;


use futures::{Future, Stream};
use mtproto::network::connection::{
    Connection, ConnectionHttp, ConnectionTcpAbridged, ConnectionTcpIntermediate, ConnectionTcpFull,
};
use mtproto::network::state::State;
use mtproto::protocol::ProtocolVersion;


mod error {
    error_chain! {
        links {
            MtProto(::mtproto::Error, ::mtproto::ErrorKind);
        }
    }
}


/// Initialize session and execute authorization.
fn processed_auth<C, F>(conn_fut: F, tag: &'static str)
    -> Box<Future<Item = (), Error = ()> + Send>
    where C: Connection,
          F: Future<Item = C, Error = mtproto::Error> + Send + 'static,
{
    Box::new(conn_fut.and_then(|conn| {
        let state = State::new(ProtocolVersion::V1);
        mtproto::rpc::auth::auth_with_state(state, conn).map_err(|(_, _, e)| e)
    }).map(move |(state, _conn)| {
        println!("Success ({}): state = {:?}", tag, state);
    }).map_err(move |e| {
        println!("{} ({})", e, tag);
        error!("{:?}", e);
    }))
}

fn main() {
    env_logger::init();
    dotenv::dotenv().ok();  // Fail silently if no .env is present

    tokio::run(futures::stream::futures_unordered(vec![
        processed_auth(ConnectionTcpAbridged::with_default_server(), "tcp-abridged"),
        processed_auth(ConnectionTcpIntermediate::with_default_server(), "tcp-intermediate"),
        processed_auth(ConnectionTcpFull::with_default_server(), "tcp-full"),
        processed_auth(ConnectionHttp::with_default_server(), "http"),
    ]).for_each(|_| Ok(())));
}

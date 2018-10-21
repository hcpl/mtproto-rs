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
use mtproto::{
    network::auth,
    network::connection::{
        DEFAULT_SERVER_ADDR,
        Connection, ConnectionHttp, ConnectionTcpAbridged, ConnectionTcpIntermediate, ConnectionTcpFull,
    },
    network::state::State,
    protocol::ProtocolVersion,
};


mod error {
    error_chain! {
        links {
            MtProto(::mtproto::Error, ::mtproto::ErrorKind);
        }
    }
}


/// Initialize session and execute authorization.
fn processed_auth<C>(tag: &'static str)
    -> Box<Future<Item = (), Error = ()> + Send>
where
    C: Connection,
{
    let state = State::new(ProtocolVersion::V1);

    Box::new(auth::connect_auth_with_state_retryable::<C>(state, *DEFAULT_SERVER_ADDR, 5, 50)
        .map(move |(state, _conn)| {
            println!("Success ({}): state = {:?}", tag, state);
        })
        .map_err(move |(_state, e)| {
            println!("{} ({})", e, tag);
            error!("{:?}", e);
        }))
}

fn main() {
    env_logger::init();
    dotenv::dotenv().ok();  // Fail silently if no .env is present

    tokio::run(futures::stream::futures_unordered(vec![
        processed_auth::<ConnectionTcpAbridged>("tcp-abridged"),
        processed_auth::<ConnectionTcpIntermediate>("tcp-intermediate"),
        processed_auth::<ConnectionTcpFull>("tcp-full"),
        processed_auth::<ConnectionHttp>("http"),
    ]).for_each(|_| Ok(())));
}

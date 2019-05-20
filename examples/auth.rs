use futures::{Future, Stream};
use log::error;
use mtproto::{
    network::auth,
    network::connection::{
        DEFAULT_SERVER_ADDR,
        Connection, ConnectionHttp, ConnectionTcpAbridged, ConnectionTcpIntermediate, ConnectionTcpFull,
    },
    network::state::State,
    protocol::ProtocolVersion,
};


/// Initialize session and execute authorization.
fn processed_auth<C>(tag: &'static str)
    -> Box<dyn Future<Item = (), Error = ()> + Send>
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

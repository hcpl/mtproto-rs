#![feature(async_await)]

use futures_util::{
    compat::Compat,
    future::FutureExt,
};
use log::error;
use mtproto::{
    async_await::network::connection::{
        Connection, ConnectionHttp, ConnectionTcpAbridged, ConnectionTcpIntermediate, ConnectionTcpFull,
    },
    async_await::network::auth,
    network::state::State,
    protocol::ProtocolVersion,
    server::DEFAULT_SERVER_ADDR,
};


/// Initialize session and execute authorization.
async fn processed_auth<C>(tag: &'static str)
where
    C: Connection,
{
    let mut state = State::new(ProtocolVersion::V1);

    match auth::connect_auth_with_state_retryable::<C>(&mut state, *DEFAULT_SERVER_ADDR, 5, 50).await {
        Ok(()) => {
            println!("Success ({}): state = {:?}", tag, state);
        },
        Err(e) => {
            println!("{} ({})", e, tag);
            error!("{:?}", e);
        },
    }
}

fn compat<Fut>(fut: Fut) -> impl futures::future::Future<Item = (), Error = ()>
where
    Fut: std::future::Future<Output = ()> + Send + 'static
{
    let mapped_ok = async move {
        let _ = fut.await;
        Ok(())
    };

    Compat::new(mapped_ok.boxed())
}

fn main() {
    env_logger::init();
    dotenv::dotenv().ok();  // Fail silently if no .env is present

    let future = async {
        tokio::spawn(compat(processed_auth::<ConnectionTcpAbridged>("tcp-abridged")));
        tokio::spawn(compat(processed_auth::<ConnectionTcpIntermediate>("tcp-intermediate")));
        tokio::spawn(compat(processed_auth::<ConnectionTcpFull>("tcp-full")));
        tokio::spawn(compat(processed_auth::<ConnectionHttp>("http")));
    };

    tokio::run(compat(future));
}

use std::time::Duration;

use futures::Future;
use log::warn;
use tokio_timer;

use crate::error::{self, ErrorKind};


pub(super) fn chain_retryable<Fut, S>(
    initial_state: S,
    new_fut: fn(S) -> Fut,
    split_error: fn(Fut::Error) -> (S, error::Error),
    merge_error: fn(S, error::Error) -> Fut::Error,
    get_error_kind: fn(&Fut::Error) -> &error::ErrorKind,
    retries: usize,
    retry_delay_millis: u64,
) -> impl Future<Item = Fut::Item, Error = Fut::Error>
where
    Fut: Future,
{
    use futures::future;

    future::loop_fn((0, initial_state), move |(retry, state)| {
        new_fut(state).then(move |res| match res {
            Ok(value) => future::Either::A(future::ok(future::Loop::Break(value))),
            Err(error) => match get_error_kind(&error) {
                // Only retry for connections that received a TCP packet with RST flag
                ErrorKind::ReceivedPacketWithRst if retry < retries => {
                    warn!("Performing retry #{} in {}ms...", retry + 1, retry_delay_millis);

                    let duration = Duration::from_millis(retry_delay_millis);
                    let (new_state, cause) = split_error(error);

                    future::Either::B(tokio_timer::sleep(duration).then(move |res| match res {
                        Ok(()) => Ok(future::Loop::Continue((retry + 1, new_state))),
                        Err(e) => {
                            let chained = cause.chain_err(|| ErrorKind::TokioTimer(e));
                            Err(merge_error(new_state, chained))
                        },
                    }))
                },
                // Other errors should be propagated
                _ => future::Either::A(future::err(error)),
            },
        })
    })
}

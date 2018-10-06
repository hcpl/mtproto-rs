use std::fmt;

use futures::{
    self, Future, IntoFuture, Stream,
    sync::mpsc,
};
use serde::ser::Serialize;
use serde::de::DeserializeOwned;
use tokio_executor;

use ::error::{self, ErrorKind};
use ::network::{
    connection::Connection,
    state::State,
};
use ::protocol::ProtocolVersion;
use ::rpc::auth;
use ::tl::TLObject;
use ::tl::message::{Message, RawMessage};


pub fn new<C: Connection>(conn: C, version: ProtocolVersion) -> SenderDisconnected<C> {
    SenderDisconnected { state: State::new(version), conn }
}


#[derive(Debug)]
pub struct SenderDisconnected<C> {
    state: State,
    conn: C,
}

#[derive(Debug)]
pub struct SenderConnected {
    state: State,
    send_queue_send: mpsc::UnboundedSender<RawMessage>,
    recv_queue_recv: mpsc::UnboundedReceiver<RawMessage>,
    pending_messages: Vec<RawMessage>,
}

impl<C: Connection> SenderDisconnected<C> {
    pub fn connect(self) -> impl Future<Item = SenderConnected, Error = error::Error> {
        self.authenticate().map(|sender_disconnd| {
            let Self { state, conn } = sender_disconnd;

            let (send_conn, recv_conn) = conn.split();
            let (send_queue_send, send_queue_recv) = mpsc::unbounded();
            let (recv_queue_send, recv_queue_recv) = mpsc::unbounded();
            let pending_messages = vec![];

            let send_loop_fut = send_loop::SendLoop::start(true, send_conn, send_queue_recv);
            let recv_loop_fut = recv_loop::RecvLoop::start(true, recv_conn, recv_queue_send);

            tokio_executor::spawn(send_loop_fut
                .map_err(|e| eprintln!("error from send loop: {} ({:?})", e, e)));
            tokio_executor::spawn(recv_loop_fut
                .map_err(|e| eprintln!("error from recv loop: {} ({:?})", e, e)));

            SenderConnected { state, send_queue_send, recv_queue_recv, pending_messages }
        })
    }

    fn authenticate(self) -> impl Future<Item = Self, Error = error::Error> {
        if self.state.auth_key.is_none() {
            futures::future::Either::A(self.impl_authenticate())
        } else {
            warn!("User is already authenticated!");
            // FIXME: Return "already authenticated" error here?
            futures::future::Either::B(futures::future::ok(self))
        }
    }

    fn impl_authenticate(self) -> impl Future<Item = Self, Error = error::Error> {
        let Self { state, conn } = self;

        auth::auth_with_state(conn, state).map(move |values| {
            Self {
                state: values.state,
                conn: values.conn,
            }
        })
    }
}

impl SenderConnected {
    pub fn send<T>(mut self, request_data: T) -> impl Future<Item = Self, Error = error::Error>
    where
        T: fmt::Debug + Serialize + TLObject + Send,
    {
        self.state.create_message::<T, Message<T>>(request_data).and_then(|message| {
            message.to_raw(self.state.auth_raw_key().unwrap(), self.state.version)
        }).into_future().and_then(|raw_message| {
            self.send_raw(raw_message)
        })
    }

    pub fn send_raw(self, raw_message: RawMessage) -> impl Future<Item = Self, Error = error::Error> {
        let Self { state, send_queue_send, recv_queue_recv, pending_messages } = self;

        send_queue_send.unbounded_send(raw_message).map_err(|e| {
            ErrorKind::UnboundedSenderUnboundedSend(e.into_inner()).into()
        }).into_future().and_then(|()| {
            Ok(Self { state, send_queue_send, recv_queue_recv, pending_messages })
        })
    }

    pub fn recv<U>(self) -> impl Future<Item = (Self, Option<U>), Error = error::Error>
    where
        U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        fn message_from_raw<U>(raw_message: &RawMessage, state: &State) -> error::Result<Message<U>>
        where
            U: fmt::Debug + DeserializeOwned + TLObject + Send,
        {
            Message::<U>::from_raw(
                raw_message,
                state.auth_raw_key().unwrap(),  // FIXME
                state.version,
            )
        }

        let Self { state, send_queue_send, recv_queue_recv, mut pending_messages } = self;

        let message = swap_remove_transformed(&mut pending_messages, |raw_message| {
            match message_from_raw(&raw_message, &state) {
                Ok(message) => Some(message),
                // FIXME: there can be other errors
                Err(_) => None,
            }
        });

        let sender_connd = Self { state, send_queue_send, recv_queue_recv, pending_messages };

        if let Some(message) = message {
            let body = message.into_body();
            return futures::future::Either::A(futures::future::ok((sender_connd, Some(body))));
        }

        futures::future::Either::B(futures::future::loop_fn(sender_connd, |sender_connd| {
            sender_connd.recv_raw().map(|(mut sender_connd, raw_message)| {
                match raw_message {
                    Some(raw_message) => match message_from_raw(&raw_message, &sender_connd.state) {
                        Ok(message) => {
                            let body = message.into_body();
                            futures::future::Loop::Break((sender_connd, Some(body)))
                        },
                        // FIXME: there can be other errors
                        Err(_) => {
                            sender_connd.pending_messages.push(raw_message);
                            futures::future::Loop::Continue(sender_connd)
                        },
                    },
                    None => futures::future::Loop::Break((sender_connd, None)),
                }
            })
        }))
    }

    pub fn recv_raw(self)
        -> impl Future<Item = (Self, Option<RawMessage>), Error = error::Error>
    {
        let Self { state, send_queue_send, recv_queue_recv, pending_messages } = self;

        recv_queue_recv.into_future().map(|(raw_message, recv_queue_recv)| {
            let sender_connd = Self {
                state, send_queue_send, recv_queue_recv, pending_messages,
            };

            (sender_connd, raw_message)
        }).map_err(|((), _recv_queue_recv)| unreachable!())
    }
}

fn swap_remove_transformed<T, U, F>(vec: &mut Vec<T>, f: F) -> Option<U>
where
    F: Fn(&T) -> Option<U>,
{
    for i in 0..vec.len() {
        if let Some(value) = f(&vec[i]) {
            vec.swap_remove(i);
            return Some(value);
        }
    }

    None
}


mod send_loop {
    use std::mem;

    use futures::{
        Async, Future, Poll, Stream,
        sync::mpsc,
    };
    use state_machine_future::RentToOwn;

    use ::error::{self, ErrorKind};
    use ::network::connection::common::SendConnection;
    use ::tl::message::RawMessage;


    #[derive(StateMachineFuture)]
    pub(super) enum SendLoop<S: SendConnection> {
        #[state_machine_future(start, transitions(GotRawMessageFromQueue, Closing))]
        Start {
            user_connected: bool,
            send_conn: S,
            send_queue_recv: mpsc::UnboundedReceiver<RawMessage>,
        },

        #[state_machine_future(transitions(Start))]
        GotRawMessageFromQueue {
            user_connected: bool,
            send_queue_recv: mpsc::UnboundedReceiver<RawMessage>,
            send_fut: Box<Future<Item = S, Error = error::Error> + Send>,
        },

        #[state_machine_future(transitions(Closed))]
        Closing{
            send_queue_recv: mpsc::UnboundedReceiver<RawMessage>,
        },

        #[state_machine_future(ready)]
        Closed(()),

        #[state_machine_future(error)]
        Error(error::Error),
    }

    impl<S: SendConnection> PollSendLoop<S> for SendLoop<S> {
        fn poll_start<'a>(
            start: &'a mut RentToOwn<'a, Start<S>>,
        ) -> Poll<AfterStart<S>, error::Error> {
            if start.user_connected {
                if let Some(raw_message) = try_ready!(start.send_queue_recv.poll()
                    .map_err(|()| ErrorKind::UnboundedReceiverPoll))
                {
                    let Start { user_connected, send_conn, send_queue_recv } = start.take();

                    transition!(GotRawMessageFromQueue {
                        user_connected,
                        send_queue_recv,
                        send_fut: send_conn.send_raw(raw_message),
                    })
                }

                Ok(Async::NotReady)
            } else {
                let Start { user_connected, send_conn, mut send_queue_recv } = start.take();

                mem::drop(user_connected);
                mem::drop(send_conn);
                send_queue_recv.close();

                transition!(Closing {
                    send_queue_recv,
                });
            }
        }

        fn poll_got_raw_message_from_queue<'a>(
            got_msg: &'a mut RentToOwn<'a, GotRawMessageFromQueue<S>>,
        ) -> Poll<AfterGotRawMessageFromQueue<S>, error::Error> {
            let send_conn = try_ready!(got_msg.send_fut.poll());

            let GotRawMessageFromQueue {
                user_connected,
                send_queue_recv,
                send_fut,
            } = got_msg.take();

            mem::drop(send_fut);

            transition!(Start {
                user_connected,
                send_conn,
                send_queue_recv,
            })
        }

        fn poll_closing<'a>(
            closing: &'a mut RentToOwn<'a, Closing>,
        ) -> Poll<AfterClosing, error::Error> {
            while let Some(raw_message) = try_ready!(closing.send_queue_recv.poll()
                .map_err(|()| ErrorKind::UnboundedReceiverPoll))
            {
                mem::drop(raw_message);
            }

            let Closing{ send_queue_recv } = closing.take();
            mem::drop(send_queue_recv);

            transition!(Closed(()))
        }
    }
}

mod recv_loop {
    use std::mem;

    use futures::{
        Future, Poll, Sink,
        sync::mpsc,
    };
    use state_machine_future::RentToOwn;

    use ::error::{self, ErrorKind};
    use ::network::connection::common::RecvConnection;
    use ::tl::message::RawMessage;

    #[derive(StateMachineFuture)]
    pub(super) enum RecvLoop<R: RecvConnection> {
        #[state_machine_future(start, transitions(RetrievingRawMessage, Closing))]
        Start {
            user_connected: bool,
            recv_conn: R,
            recv_queue_send: mpsc::UnboundedSender<RawMessage>,
        },

        #[state_machine_future(transitions(Start))]
        RetrievingRawMessage {
            user_connected: bool,
            recv_queue_send: mpsc::UnboundedSender<RawMessage>,
            recv_fut: Box<Future<Item = (R, RawMessage), Error = error::Error> + Send>,
        },

        #[state_machine_future(transitions(Closed))]
        Closing {
            recv_queue_send: mpsc::UnboundedSender<RawMessage>,
        },

        #[state_machine_future(ready)]
        Closed(()),

        #[state_machine_future(error)]
        Error(error::Error),
    }

    impl<R: RecvConnection> PollRecvLoop<R> for RecvLoop<R> {
        fn poll_start<'a>(
            start: &'a mut RentToOwn<'a, Start<R>>,
        ) -> Poll<AfterStart<R>, error::Error> {
            if start.user_connected {
                let Start { user_connected, recv_conn, recv_queue_send } = start.take();

                transition!(RetrievingRawMessage {
                    user_connected,
                    recv_queue_send,
                    recv_fut: recv_conn.recv_raw(),
                })
            } else {
                let Start { user_connected, recv_conn, recv_queue_send } = start.take();

                mem::drop(user_connected);
                mem::drop(recv_conn);

                transition!(Closing {
                    recv_queue_send,
                });
            }
        }

        fn poll_retrieving_raw_message<'a>(
            retv_raw_msg: &'a mut RentToOwn<'a, RetrievingRawMessage<R>>,
        ) -> Poll<AfterRetrievingRawMessage<R>, error::Error> {
            let (recv_conn, raw_message) = try_ready!(retv_raw_msg.recv_fut.poll());

            let RetrievingRawMessage {
                user_connected,
                recv_queue_send,
                recv_fut,
            } = retv_raw_msg.take();

            recv_queue_send.unbounded_send(raw_message)
                .map_err(|e| ErrorKind::UnboundedSenderUnboundedSend(e.into_inner()))?;

            mem::drop(recv_fut);

            transition!(Start {
                user_connected,
                recv_conn,
                recv_queue_send,
            })
        }

        fn poll_closing<'a>(
            closing: &'a mut RentToOwn<'a, Closing>,
        ) -> Poll<AfterClosing, error::Error> {
            try_ready!(closing.recv_queue_send.poll_complete()
                .map_err(|error| ErrorKind::UnboundedSenderPollComplete(error.into_inner())));

            let Closing { recv_queue_send } = closing.take();
            mem::drop(recv_queue_send);

            transition!(Closed(()))
        }
    }
}

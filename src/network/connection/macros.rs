macro_rules! generate_create_connection_methods {
    (
        connection_log_str = $connection_log_str:tt,
        ret = $self_expr:expr,
    ) => {
        pub fn connect(
            server_addr: std::net::SocketAddr,
        ) -> impl futures::future::Future<
            Item = Self,
            Error = crate::error::Error,
        >
        {
            log::info!(
                concat!("New ", $connection_log_str, " to {}"),
                server_addr,
            );

            TcpStream::connect(&server_addr).map_err(std::convert::Into::into).map($self_expr)
        }

        pub fn with_default_server() -> impl futures::future::Future<
            Item = Self,
            Error = crate::error::Error,
        >
        {
            use crate::async_await::network::connection::common::DEFAULT_SERVER_ADDR;

            Self::connect(*DEFAULT_SERVER_ADDR)
        }
    };
}

// Requires having ```pub fn send_raw<R>(self, raw_message: R)
//     -> impl Future<Item = Self, Error = (Self, R, error::Error)>
// ```
// (can be generated from `generate_send_raw_method!()`)
macro_rules! generate_send_connection_methods {
    () => {
        pub fn send_plain<T>(
            self,
            state: crate::network::state::State,
            send_data: T,
        ) -> impl futures::future::Future<
            Item = (Self, crate::network::state::State),
            Error = (Self, crate::network::state::State, T, crate::error::Error)
        >
        where
            T: std::fmt::Debug + serde::ser::Serialize + crate::tl::TLObject + std::marker::Send,
        {
            use crate::tl::message::MessagePlain;

            self.impl_send::<T, MessagePlain<T>>(state, send_data)
        }

        pub fn send<T>(
            self,
            state: crate::network::state::State,
            send_data: T,
        ) -> impl futures::future::Future<
            Item = (Self, crate::network::state::State),
            Error = (Self, crate::network::state::State, T, crate::error::Error)
        >
        where
            T: std::fmt::Debug + serde::ser::Serialize + crate::tl::TLObject + std::marker::Send,
        {
            use crate::tl::message::Message;

            self.impl_send::<T, Message<T>>(state, send_data)
        }

        fn impl_send<T, M>(
            self,
            mut state: crate::network::state::State,
            send_data: T,
        ) -> impl futures::future::Future<
            Item = (Self, crate::network::state::State),
            Error = (Self, crate::network::state::State, T, crate::error::Error)
        >
        where
            T: std::fmt::Debug + serde::ser::Serialize + crate::tl::TLObject + std::marker::Send,
            M: crate::tl::message::MessageCommon<T>,
        {
            match state.create_message2::<T, M>(send_data) {
                Err((send_data, e)) => {
                    futures::future::Either::A(futures::future::err((self, state, send_data, e)))
                },
                Ok(request_message) => {
                    log::debug!("Message to send: {:?}", request_message);

                    match request_message.to_raw(state.auth_raw_key(), state.version) {
                        Err(e) => {
                            let send_data = request_message.into_body();
                            futures::future::Either::A(futures::future::err((self, state, send_data, e)))
                        },
                        Ok(raw_message) => {
                            futures::future::Either::B(self.send_raw(raw_message).then(|res| match res {
                                Err((conn, _, e)) => Err((conn, state, request_message.into_body(), e)),
                                Ok(conn) => Ok((conn, state)),
                            }))
                        },
                    }
                },
            }
        }
    };
}

macro_rules! generate_send_raw_method {
    (
        prepare_send_data = $prepare_send_data_expr:expr,
        perform_send = $perform_send_expr:expr,
        self_to_fields = $self_to_fields_expr:expr,
        self_from_fields = $self_from_fields_expr:expr,
    ) => {
        pub fn send_raw<R>(
            mut self,
            raw_message: R,
        ) -> impl futures::future::Future<
            Item = Self,
            Error = (Self, R, crate::error::Error),
        >
        where
            R: crate::tl::message::RawMessageCommon,
        {
            log::debug!("Raw message to send: {:?}", raw_message);

            match $prepare_send_data_expr(&raw_message, &mut self) {
                Err(e) => futures::future::Either::A(futures::future::err((self, raw_message, e))),
                Ok(data) => {
                    let (socket, fields) = ($self_to_fields_expr)(self);

                    futures::future::Either::B($perform_send_expr(socket, data)
                        .map(move |socket| ($self_from_fields_expr)(socket, fields))
                        .map_err(move |(socket, _, e)| {
                            (($self_from_fields_expr)(socket, fields), raw_message, e)
                        }))
                },
            }
        }
    };
}

// Requires having ```pub fn recv_raw<S>(self)
//     -> impl Future<Item = (Self, S), Error = (Self, error::Error)>
// ```
// (can be generated from `generate_recv_raw_method!()`)
macro_rules! generate_recv_connection_methods {
    () => {
        pub fn recv_plain<U>(
            self,
            state: crate::network::state::State,
        ) -> impl futures::future::Future<
            Item = (Self, crate::network::state::State, U),
            Error = (Self, crate::network::state::State, crate::error::Error),
        >
        where
            U: std::fmt::Debug + serde::de::DeserializeOwned + crate::tl::TLObject + std::marker::Send,
        {
            use crate::tl::message::MessagePlain;

            self.impl_recv::<U, MessagePlain<U>>(state)
        }

        pub fn recv<U>(
            self,
            state: crate::network::state::State,
        ) -> impl futures::future::Future<
            Item = (Self, crate::network::state::State, U),
            Error = (Self, crate::network::state::State, crate::error::Error),
        >
        where
            U: std::fmt::Debug + serde::de::DeserializeOwned + crate::tl::TLObject + std::marker::Send,
        {
            use crate::tl::message::Message;

            self.impl_recv::<U, Message<U>>(state)
        }

        fn impl_recv<U, N>(
            self,
            state: crate::network::state::State,
        ) -> impl futures::future::Future<
            Item = (Self, crate::network::state::State, U),
            Error = (Self, crate::network::state::State, crate::error::Error),
        >
        where
            U: std::fmt::Debug + serde::de::DeserializeOwned + crate::tl::TLObject + std::marker::Send,
            N: crate::tl::message::MessageCommon<U>,
        {
            use crate::network::connection::common;

            self.recv_raw().then(|res| match res {
                Err((conn, e)) => Err((conn, state, e)),
                Ok((conn, raw_message)) => match common::from_raw::<U, N>(&raw_message, &state) {
                    Err(e) => Err((conn, state, e)),
                    Ok(message) => {
                        log::debug!("Received message: {:?}", message);
                        Ok((conn, state, message.into_body()))
                    }
                },
            })
        }
    };
}

macro_rules! generate_recv_raw_method {
    (
        parse_response = $parse_response_expr:expr,
        self_to_fields = $self_to_fields_expr:expr,
        self_from_fields = $self_from_fields_expr:expr,
    ) => {
        pub fn recv_raw<S>(
            self,
        ) -> impl futures::future::Future<
            Item = (Self, S),
            Error = (Self, crate::error::Error),
        >
        where
            S: crate::tl::message::RawMessageCommon,
        {
            let (socket, fields) = ($self_to_fields_expr)(self);

            perform_recv(socket)
                .map_err(move |(socket, e)| (($self_from_fields_expr)(socket, fields), e))
                .and_then(move |(socket, data)| {
                    let conn = ($self_from_fields_expr)(socket, fields);

                    match $parse_response_expr(&data) {
                        Ok(raw_message) => {
                            log::debug!("Received raw message: {:?}", raw_message);
                            Ok((conn, raw_message))
                        },
                        Err(e) => Err((conn, e)),
                    }
                })
        }
    };
}

// Requires having:
// * ```pub fn impl_send<T, M>(self, state: State, send_data: T)
//          -> impl Future<Item = (Self, State), Error = (Self, State, T, error::Error)>
//   ```
// * ```pub fn impl_recv<U, N>(self, state: State)
//          -> impl Future<Item = (Self, State, U), Error = (Self, State, error::Error)>
//   ```
macro_rules! generate_request_connection_methods {
    () => {
        pub fn request_plain<T, U>(
            self,
            state: crate::network::state::State,
            send_data: T,
        ) -> impl futures::future::Future<
            Item = (Self, crate::network::state::State, U),
            Error = (Self, crate::network::state::State, std::option::Option<T>, crate::error::Error),
        >
        where
            T: std::fmt::Debug + serde::ser::Serialize + crate::tl::TLObject + std::marker::Send,
            U: std::fmt::Debug + serde::de::DeserializeOwned + crate::tl::TLObject + std::marker::Send,
        {
            use crate::tl::message::MessagePlain;

            self.impl_request::<T, U, MessagePlain<T>, MessagePlain<U>>(state, send_data)
        }

        pub fn request<T, U>(
            self,
            state: crate::network::state::State,
            send_data: T,
        ) -> impl futures::future::Future<
            Item = (Self, crate::network::state::State, U),
            Error = (Self, crate::network::state::State, std::option::Option<T>, crate::error::Error),
        >
        where
            T: std::fmt::Debug + serde::ser::Serialize + crate::tl::TLObject + std::marker::Send,
            U: std::fmt::Debug + serde::de::DeserializeOwned + crate::tl::TLObject + std::marker::Send,
        {
            use crate::tl::message::Message;

            self.impl_request::<T, U, Message<T>, Message<U>>(state, send_data)
        }

        fn impl_request<T, U, M, N>(
            self,
            state: crate::network::state::State,
            send_data: T,
        ) -> impl futures::future::Future<
            Item = (Self, crate::network::state::State, U),
            Error = (Self, crate::network::state::State, std::option::Option<T>, crate::error::Error),
        >
        where
            T: std::fmt::Debug + serde::ser::Serialize + crate::tl::TLObject + std::marker::Send,
            U: std::fmt::Debug + serde::de::DeserializeOwned + crate::tl::TLObject + std::marker::Send,
            M: crate::tl::message::MessageCommon<T>,
            N: crate::tl::message::MessageCommon<U> + 'static,
        {
            self.impl_send::<T, M>(state, send_data)
                .map_err(|(conn, state, send_data, e)| (conn, state, Some(send_data), e))
                .and_then(|(conn, state)| {
                    conn.impl_recv::<U, N>(state).map_err(|(conn, state, e)| (conn, state, None, e))
                })
        }
    };
}

// Requires having:
// * ```pub fn send_plain<T>(self, state: State, send_data: T)
//          -> impl Future<Item = (Self, State), Error = (Self, State, T, error::Error)>
//   ```
// * ```pub fn send<T>(self, state: State, send_data: T)
//          -> impl Future<Item = (Self, State), Error = (Self, State, T, error::Error)>
//   ```
// * ```pub fn send_raw<R>(self, raw_message: R)
//          -> impl Future<Item = Self, Error = (Self, R, error::Error)>
//   ```
macro_rules! delegate_impl_send_connection_for {
    ($type:ident) => {
        impl crate::network::connection::SendConnection for $type {
            fn send_plain<T>(
                self,
                state: crate::network::state::State,
                send_data: T,
            ) -> std::boxed::Box<dyn futures::future::Future<
                Item = (Self, crate::network::state::State),
                Error = (Self, crate::network::state::State, T, crate::error::Error)
            > + std::marker::Send>
            where
                T: std::fmt::Debug + serde::ser::Serialize + crate::tl::TLObject + std::marker::Send,
            {
                std::boxed::Box::new(self.send_plain(state, send_data))
            }

            fn send<T>(
                self,
                state: crate::network::state::State,
                send_data: T,
            ) -> std::boxed::Box<dyn futures::future::Future<
                Item = (Self, crate::network::state::State),
                Error = (Self, crate::network::state::State, T, crate::error::Error)
            > + std::marker::Send>
            where
                T: std::fmt::Debug + serde::ser::Serialize + crate::tl::TLObject + std::marker::Send,
            {
                std::boxed::Box::new(self.send(state, send_data))
            }

            fn send_raw<R>(
                self,
                raw_message: R,
            ) -> std::boxed::Box<dyn futures::future::Future<
                Item = Self,
                Error = (Self, R, crate::error::Error),
            > + std::marker::Send>
            where
                R: crate::tl::message::RawMessageCommon,
            {
                std::boxed::Box::new(self.send_raw(raw_message))
            }
        }
    };
}

// Requires having:
// * ```pub fn recv_plain<U>(self, state: State)
//          -> impl Future<Item = (Self, State, U), Error = (Self, State, error::Error)>
//   ```
// * ```pub fn recv<U>(self, state: State)
//          -> impl Future<Item = (Self, State, U), Error = (Self, State, error::Error)>
//   ```
// * ```pub fn recv_raw<S>(self)
//          -> impl Future<Item = (Self, S), Error = (Self, error::Error)>
//   ```
macro_rules! delegate_impl_recv_connection_for {
    ($type:ident) => {
        impl crate::network::connection::RecvConnection for $type {
            fn recv_plain<U>(
                self,
                state: crate::network::state::State,
            ) -> std::boxed::Box<dyn futures::future::Future<
                Item = (Self, crate::network::state::State, U),
                Error = (Self, crate::network::state::State, crate::error::Error),
            > + std::marker::Send>
            where
                U: std::fmt::Debug + serde::de::DeserializeOwned + crate::tl::TLObject + std::marker::Send,
            {
                std::boxed::Box::new(self.recv_plain(state))
            }

            fn recv<U>(
                self,
                state: crate::network::state::State,
            ) -> std::boxed::Box<dyn futures::future::Future<
                Item = (Self, crate::network::state::State, U),
                Error = (Self, crate::network::state::State, crate::error::Error),
            > + std::marker::Send>
            where
                U: std::fmt::Debug + serde::de::DeserializeOwned + crate::tl::TLObject + std::marker::Send,
            {
                std::boxed::Box::new(self.recv(state))
            }

            fn recv_raw<S>(
                self,
            ) -> std::boxed::Box<dyn futures::future::Future<
                Item = (Self, S),
                Error = (Self, crate::error::Error),
            > + std::marker::Send>
            where
                S: crate::tl::message::RawMessageCommon,
            {
                std::boxed::Box::new(self.recv_raw())
            }
        }
    };
}

// Requires having:
// * ```pub fn connect(server_addr: SocketAddr)
//          -> impl Future<Item = Self, Error = error::Error>
//   ```
// * ```pub fn with_default_server()
//          -> impl Future<Item = Self, Error = error::Error>
//   ```
// * ```pub fn request_plain<T, U>(self, state: State, send_data: T)
//          -> impl Future<Item = (Self, State, U), Error = (Self, State, Option<T>, error::Error)>
//   ```
// * ```pub fn request<T, U>(self, state: State, send_data: T)
//          -> impl Future<Item = (Self, State, U), Error = (Self, State, Option<T>, error::Error)>
//   ```
// * ```pub fn split(self)
//          -> (Self::SendConnection, Self::RecvConnection)
//   ```
macro_rules! delegate_impl_connection_for {
    ($type:ident with SendConnection = $send_type:ident, RecvConnection = $recv_type:ident) => {
        impl crate::network::connection::Connection for $type {
            type SendConnection = $send_type;
            type RecvConnection = $recv_type;

            fn connect(
                server_addr: std::net::SocketAddr,
            ) -> std::boxed::Box<dyn futures::future::Future<
                Item = Self,
                Error = crate::error::Error,
            > + std::marker::Send>
            {
                std::boxed::Box::new(Self::connect(server_addr))
            }

            fn with_default_server() -> std::boxed::Box<dyn futures::future::Future<
                Item = Self,
                Error = crate::error::Error,
            > + std::marker::Send>
            {
                std::boxed::Box::new(Self::with_default_server())
            }

            fn request_plain<T, U>(
                self,
                state: crate::network::state::State,
                send_data: T,
            ) -> std::boxed::Box<dyn futures::future::Future<
                Item = (Self, crate::network::state::State, U),
                Error = (Self, crate::network::state::State, std::option::Option<T>, crate::error::Error),
            > + std::marker::Send>
            where
                T: std::fmt::Debug + serde::ser::Serialize + crate::tl::TLObject + std::marker::Send,
                U: std::fmt::Debug + serde::de::DeserializeOwned + crate::tl::TLObject + std::marker::Send,
            {
                Box::new(self.request_plain(state, send_data))
            }

            fn request<T, U>(
                self,
                state: crate::network::state::State,
                send_data: T,
            ) -> std::boxed::Box<dyn futures::future::Future<
                Item = (Self, crate::network::state::State, U),
                Error = (Self, crate::network::state::State, std::option::Option<T>, crate::error::Error),
            > + std::marker::Send>
            where
                T: std::fmt::Debug + serde::ser::Serialize + crate::tl::TLObject + std::marker::Send,
                U: std::fmt::Debug + serde::de::DeserializeOwned + crate::tl::TLObject + std::marker::Send,
            {
                Box::new(self.request(state, send_data))
            }

            fn split(self) -> (Self::SendConnection, Self::RecvConnection) {
                self.split()
            }
        }
    };
}

// Requires having `pub async fn connect(server_addr: SocketAddr) -> error::Result<Self>`
macro_rules! generate_create_connection_methods_for {
    (
        $type:ident,
        connection_log_str = $connection_log_str:tt,
        ret = $self_expr:expr
    ) => {
        #[async_transform::impl_async_methods_to_impl_futures]
        impl $type {
            pub async fn connect(server_addr: std::net::SocketAddr) -> crate::error::Result<Self> {
                log::info!(
                    concat!("New ", $connection_log_str, " to {}"),
                    server_addr,
                );
                let socket = TcpStream::connect(&server_addr).compat().await?;

                Ok($self_expr)
            }

            pub async fn with_default_server() -> crate::error::Result<Self> {
                use crate::async_await::network::connection::common::DEFAULT_SERVER_ADDR;

                Self::connect(*DEFAULT_SERVER_ADDR).await
            }
        }
    };
}

// Requires having `pub async fn send_raw<R>(&mut self, raw_message: &R) -> error::Result<()>`
macro_rules! generate_send_connection_methods_for {
    ($type:ident) => {
        #[async_transform::impl_async_methods_to_impl_futures]
        impl $type {
            pub async fn send_plain<T>(
                &mut self,
                state: &mut crate::network::state::State,
                send_data: T,
            ) -> crate::error::Result<()>
            where
                T: std::fmt::Debug + serde::ser::Serialize + crate::tl::TLObject + std::marker::Send,
            {
                self.impl_send::<T, crate::tl::message::MessagePlain<T>>(state, send_data).await
            }

            pub async fn send<T>(
                &mut self,
                state: &mut crate::network::state::State,
                send_data: T,
            ) -> crate::error::Result<()>
            where
                T: std::fmt::Debug + serde::ser::Serialize + crate::tl::TLObject + std::marker::Send,
            {
                self.impl_send::<T, crate::tl::message::Message<T>>(state, send_data).await
            }

            async fn impl_send<T, M>(
                &mut self,
                state: &mut crate::network::state::State,
                send_data: T,
            ) -> crate::error::Result<()>
            where
                T: std::fmt::Debug + serde::ser::Serialize + crate::tl::TLObject + std::marker::Send,
                M: crate::tl::message::MessageCommon<T>,
            {
                let request_message = state.create_message::<T, M>(send_data)?;
                log::debug!("Message to send: {:?}", request_message);

                let raw_message = request_message.to_raw(state.auth_raw_key(), state.version)?;
                self.send_raw(&raw_message).await
            }
        }
    };
}

macro_rules! generate_send_raw_method_for {
    ($type:ident, prepare_send_data = $prepare_send_data_expr:expr, perform_send = $perform_send_expr:expr) => {
        #[async_transform::impl_async_methods_to_impl_futures]
        impl $type {
            pub async fn send_raw<R>(&mut self, raw_message: &R) -> crate::error::Result<()>
            where
                R: crate::tl::message::RawMessageCommon,
            {
                log::debug!("Raw message to send: {:?}", raw_message);
                let data = $prepare_send_data_expr;
                $perform_send_expr
            }
        }
    };
}

// Requires having `pub async fn recv_raw<S>(&mut self) -> error::Result<S>`
macro_rules! generate_recv_connection_methods_for {
    ($type:ident) => {
        #[async_transform::impl_async_methods_to_impl_futures]
        impl $type {
            pub async fn recv_plain<U>(
                &mut self,
                state: &mut crate::network::state::State,
            ) -> crate::error::Result<U>
            where
                U: std::fmt::Debug + serde::de::DeserializeOwned + crate::tl::TLObject + std::marker::Send,
            {
                self.impl_recv::<U, crate::tl::message::MessagePlain<U>>(state).await
            }

            pub async fn recv<U>(
                &mut self,
                state: &mut crate::network::state::State,
            ) -> crate::error::Result<U>
            where
                U: std::fmt::Debug + serde::de::DeserializeOwned + crate::tl::TLObject + std::marker::Send,
            {
                self.impl_recv::<U, crate::tl::message::Message<U>>(state).await
            }

            async fn impl_recv<U, N>(
                &mut self,
                state: &mut crate::network::state::State,
            ) -> crate::error::Result<U>
            where
                U: std::fmt::Debug + serde::de::DeserializeOwned + crate::tl::TLObject + std::marker::Send,
                N: crate::tl::message::MessageCommon<U>,
            {
                let raw_message = self.recv_raw().await?;
                let message = common::from_raw::<U, N>(&raw_message, state)?;
                log::debug!("Received message: {:?}", message);

                Ok(message.into_body())
            }
        }
    };
}

macro_rules! generate_recv_raw_method_for {
    ($type:ident, perform_recv = $perform_recv_expr:expr, parse_response = $parse_response_expr:expr) => {
        #[async_transform::impl_async_methods_to_impl_futures]
        impl $type {
            pub async fn recv_raw<S>(&mut self) -> crate::error::Result<S>
            where
                S: crate::tl::message::RawMessageCommon,
            {
                let data = $perform_recv_expr;
                let raw_message = $parse_response_expr;
                log::debug!("Received raw message: {:?}", raw_message);

                Ok(raw_message)
            }
        }
    };
}


// Requires having `pub async fn recv_raw<S>(&mut self) -> error::Result<S>`
// Requires having:
// * `pub async fn impl_send<T, M>(&mut self, state: &mut State, send_data: T) -> error::Result<()>`
// * `pub async fn impl_recv<U, N>(&mut self, state: &mut State) -> error::Result<U>`
macro_rules! generate_request_connection_methods_for {
    ($type:ident) => {
        #[async_transform::impl_async_methods_to_impl_futures]
        impl $type {
            pub async fn request_plain<T, U>(
                &mut self,
                state: &mut crate::network::state::State,
                request_data: T,
            ) -> error::Result<U>
            where
                T: std::fmt::Debug + serde::ser::Serialize + crate::tl::TLObject + std::marker::Send,
                U: std::fmt::Debug + serde::de::DeserializeOwned + crate::tl::TLObject + std::marker::Send,
            {
                self.impl_request::<
                    T, U, crate::tl::message::MessagePlain<T>, crate::tl::message::MessagePlain<U>
                >(state, request_data).await
            }

            pub async fn request<T, U>(
                &mut self,
                state: &mut crate::network::state::State,
                request_data: T,
            ) -> error::Result<U>
            where
                T: std::fmt::Debug + serde::ser::Serialize + crate::tl::TLObject + std::marker::Send,
                U: std::fmt::Debug + serde::de::DeserializeOwned + crate::tl::TLObject + std::marker::Send,
            {
                self.impl_request::<
                    T, U, crate::tl::message::Message<T>, crate::tl::message::Message<U>
                >(state, request_data).await
            }

            async fn impl_request<T, U, M, N>(
                &mut self,
                state: &mut crate::network::state::State,
                request_data: T,
            ) -> error::Result<U>
            where
                T: std::fmt::Debug + serde::ser::Serialize + crate::tl::TLObject + std::marker::Send,
                U: std::fmt::Debug + serde::de::DeserializeOwned + crate::tl::TLObject + std::marker::Send,
                M: crate::tl::message::MessageCommon<T>,
                N: crate::tl::message::MessageCommon<U>,
            {
                self.impl_send::<T, M>(state, request_data).await?;
                self.impl_recv::<U, N>(state).await
            }
        }
    };
}

macro_rules! delegate_impl_send_connection_for {
    ($type:ident) => {
        #[async_transform::trait_impl_async_methods_to_box_futures]
        impl crate::async_await::network::connection::SendConnection for $type {
            async fn send_plain<T>(
                &mut self,
                state: &mut crate::network::state::State,
                send_data: T,
            ) -> crate::error::Result<()>
            where
                T: std::fmt::Debug + serde::ser::Serialize + crate::tl::TLObject + std::marker::Send,
            {
                self.send_plain(state, send_data).await
            }

            async fn send<T>(
                &mut self,
                state: &mut crate::network::state::State,
                send_data: T,
            ) -> crate::error::Result<()>
            where
                T: std::fmt::Debug + serde::ser::Serialize + crate::tl::TLObject + std::marker::Send,
            {
                self.send(state, send_data).await
            }

            async fn send_raw<R>(&mut self, raw_message: &R) -> crate::error::Result<()>
            where
                R: crate::tl::message::RawMessageCommon + std::marker::Sync,
            {
                self.send_raw(raw_message).await
            }
        }
    };
}

macro_rules! delegate_impl_recv_connection_for {
    ($type:ident) => {
        #[async_transform::trait_impl_async_methods_to_box_futures]
        impl crate::async_await::network::connection::RecvConnection for $type {
            async fn recv_plain<U>(
                &mut self,
                state: &mut crate::network::state::State,
            ) -> crate::error::Result<U>
            where
                U: std::fmt::Debug + serde::de::DeserializeOwned + crate::tl::TLObject + std::marker::Send,
            {
                self.recv_plain(state).await
            }

            async fn recv<U>(
                &mut self,
                state: &mut crate::network::state::State,
            ) -> crate::error::Result<U>
            where
                U: std::fmt::Debug + serde::de::DeserializeOwned + crate::tl::TLObject + std::marker::Send,
            {
                self.recv(state).await
            }

            async fn recv_raw<S>(&mut self) -> crate::error::Result<S>
            where
                S: crate::tl::message::RawMessageCommon,
            {
                self.recv_raw().await
            }
        }
    };
}

macro_rules! delegate_impl_connection_for {
    ($type:ident with SendConnection = $send_type:ident, RecvConnection = $recv_type:ident) => {
        #[async_transform::trait_impl_async_methods_to_box_futures]
        impl crate::async_await::network::connection::Connection for $type {
            type SendConnection = $send_type;
            type RecvConnection = $recv_type;

            async fn connect(server_addr: std::net::SocketAddr) -> crate::error::Result<Self> {
                Self::connect(server_addr).await
            }

            async fn with_default_server() -> crate::error::Result<Self> {
                Self::with_default_server().await
            }

            async fn request_plain<T, U>(
                &mut self,
                state: &mut crate::network::state::State,
                request_data: T,
            ) -> crate::error::Result<U>
            where
                T: std::fmt::Debug + serde::ser::Serialize + crate::tl::TLObject + std::marker::Send,
                U: std::fmt::Debug + serde::de::DeserializeOwned + crate::tl::TLObject + std::marker::Send,
            {
                self.request_plain(state, request_data).await
            }

            async fn request<T, U>(
                &mut self,
                state: &mut crate::network::state::State,
                request_data: T,
            ) -> crate::error::Result<U>
            where
                T: std::fmt::Debug + serde::ser::Serialize + crate::tl::TLObject + std::marker::Send,
                U: std::fmt::Debug + serde::de::DeserializeOwned + crate::tl::TLObject + std::marker::Send,
            {
                self.request(state, request_data).await
            }

            fn split(self) -> (Self::SendConnection, Self::RecvConnection) {
                self.split()
            }
        }
    };
}

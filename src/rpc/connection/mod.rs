use std::fmt;
use std::net::SocketAddr;

use hyper;
use futures::{self, Future};
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use tokio_core::reactor::Handle;

use error;
use rpc::{MessageType, Session};
use tl::TLObject;


/// Helper macros for use in `tcp` and `http` modules
macro_rules! bailf {
    ($e:expr) => {
        return Box::new(::futures::future::err($e.into()))
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

pub mod tcp;
pub mod http;

pub use self::tcp::{TcpConnection, TcpMode};
pub use self::http::HttpConnection;


lazy_static! {
    pub static ref TCP_SERVER_ADDRS: [SocketAddr; 1] = [
        ([149,154,167,51], 443).into(),
    ];

    pub static ref HTTP_SERVER_ADDRS: [hyper::Uri; 1] = [
        "http://149.154.167.51:443/api".parse().unwrap(),  // safe to unwrap
    ];
}


#[derive(Debug)]
pub enum Connection {
    Tcp(TcpConnection),
    Http(HttpConnection),
}

impl Connection {
    pub fn new(handle: Handle, conn_config: ConnectionConfig)
        -> Box<Future<Item = Connection, Error = error::Error>>
    {
        match conn_config {
            ConnectionConfig::Tcp(tcp_mode, server_addr) => {
                Box::new(TcpConnection::new(handle, tcp_mode, server_addr).map(Connection::Tcp))
            },
            ConnectionConfig::Http(server_addr) => {
                Box::new(futures::future::ok(Connection::Http(HttpConnection::new(handle, server_addr))))
            },
        }
    }

    pub fn default_with_handle(handle: Handle)
        -> Box<Future<Item = Connection, Error = error::Error>>
    {
        Connection::tcp_default_with_handle(handle)
    }

    pub fn tcp_default_with_handle(handle: Handle)
        -> Box<Future<Item = Connection, Error = error::Error>>
    {
        Box::new(TcpConnection::default_with_handle(handle).map(|conn| {
            Connection::Tcp(conn)
        }))
    }

    pub fn http_default_with_handle(handle: Handle) -> Connection {
        Connection::Http(HttpConnection::default_with_handle(handle))
    }

    /// Delegates to `request()` methods of inner connection types.
    pub fn request<T, U>(self,
                         session: Session,
                         request_data: T,
                         request_message_type: MessageType,
                         response_message_type: MessageType)
                        -> Box<Future<Item = (Connection, Session, U), Error = error::Error>>
        where T: fmt::Debug + Serialize + TLObject,
              U: fmt::Debug + DeserializeOwned + TLObject,
    {
        match self {
            Connection::Tcp(conn) => {
                Box::new(conn.request(session, request_data, request_message_type, response_message_type)
                    .map(|(tcp_conn, session, response)| (Connection::Tcp(tcp_conn), session, response)))
            },
            Connection::Http(conn) => {
                Box::new(conn.request(session, request_data, request_message_type, response_message_type)
                    .map(|(http_conn, session, response)| (Connection::Http(http_conn), session, response)))
            },
        }
    }
}


#[derive(Clone, Debug, PartialEq)]
pub enum ConnectionConfig {
    Tcp(TcpMode, SocketAddr),
    Http(hyper::Uri),
}

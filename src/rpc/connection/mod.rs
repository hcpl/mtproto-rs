use std::fmt;
use std::net::SocketAddr;

use hyper;
use futures::Future;
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
    pub fn default_with_handle(handle: Handle) -> Box<Future<Item = Connection, Error = error::Error>> {
        Connection::tcp_default(handle)
    }

    pub fn tcp_default(handle: Handle) -> Box<Future<Item = Connection, Error = error::Error>> {
        Box::new(TcpConnection::default_with_handle(handle).map(|conn| {
            Connection::Tcp(conn)
        }))
    }

    pub fn http_default(handle: Handle) -> Connection {
        Connection::Http(HttpConnection::default_with_handle(handle))
    }

    pub fn request<T, U>(self,
                         session: Session,
                         request_data: T,
                         request_message_type: MessageType,
                         response_message_type: MessageType)
                        -> Box<Future<Item = (Connection, Option<U>, Session), Error = error::Error>>
        where T: fmt::Debug + Serialize + TLObject,
              U: fmt::Debug + DeserializeOwned + TLObject,
    {
        match self {
            Connection::Tcp(conn) => {
                Box::new(conn.request(session, request_data, request_message_type, response_message_type)
                    .map(|(tcp_conn, response, session)| (Connection::Tcp(tcp_conn), response, session)))
            },
            Connection::Http(conn) => {
                Box::new(conn.request(session, request_data, request_message_type, response_message_type)
                    .map(|(http_conn, response, session)| (Connection::Http(http_conn), response, session)))
            },
        }
    }
}

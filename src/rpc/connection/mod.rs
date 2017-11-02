use std::net::SocketAddr;

use hyper;


/// Helper macros for use in `tcp` and `http` modules
macro_rules! bailf {
    ($e:expr) => {
        return Box::new(futures::future::err($e.into()))
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

impl Default for Connection {
    fn default() -> Connection {
        Connection::tcp_default()
    }
}

impl Connection {
    pub fn tcp_default() -> Connection {
        Connection::Tcp(TcpConnection::default())
    }

    pub fn http_default() -> Connection {
        Connection::Http(HttpConnection::default())
    }
}

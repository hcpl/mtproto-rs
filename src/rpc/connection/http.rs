use hyper;

use super::HTTP_SERVER_ADDRS;


#[derive(Debug)]
pub struct HttpConnection {
    server_addr: hyper::Uri,
}

impl Default for HttpConnection {
    fn default() -> HttpConnection {
        HttpConnection {
            server_addr: HTTP_SERVER_ADDRS[0].clone(),
        }
    }
}

impl HttpConnection {
    pub fn new(server_addr: hyper::Uri) -> HttpConnection {
        HttpConnection { server_addr }
    }
}

use std::net::SocketAddr;

use lazy_static::lazy_static;


lazy_static! {
    pub static ref SERVER_ADDRS: [SocketAddr; 1] = [
        ([149, 154, 167, 51], 443).into(),
    ];

    pub static ref DEFAULT_SERVER_ADDR: SocketAddr = SERVER_ADDRS[0];
}

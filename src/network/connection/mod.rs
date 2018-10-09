pub mod common;
pub mod http;
pub mod tcp_abridged;
pub mod tcp_common;
pub mod tcp_intermediate;
pub mod tcp_full;

pub use self::common::{SERVER_ADDRS, Connection};
pub use self::http::ConnectionHttp;
pub use self::tcp_abridged::ConnectionTcpAbridged;
pub use self::tcp_intermediate::ConnectionTcpIntermediate;
pub use self::tcp_full::ConnectionTcpFull;

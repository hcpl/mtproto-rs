#[macro_use]
mod macros;

pub mod common;
pub mod http;
pub mod tcp_abridged;
pub mod tcp_common;
pub mod tcp_full;
pub mod tcp_intermediate;

pub use self::common::{Connection, RecvConnection, SendConnection};
pub use self::http::ConnectionHttp;
pub use self::tcp_abridged::ConnectionTcpAbridged;
pub use self::tcp_full::ConnectionTcpFull;
pub use self::tcp_intermediate::ConnectionTcpIntermediate;

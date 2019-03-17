use byteorder::{ByteOrder, LittleEndian};
use error_chain::bail;
use log::debug;
use serde_mtproto;

use crate::error::{self, ErrorKind};
use crate::tl::message::{RawMessageCommon, RawMessageSeedCommon};


pub(super) fn parse_response<S>(response_bytes: &[u8]) -> error::Result<S>
where
    S: RawMessageCommon,
{
    debug!("Response bytes: len = {} --- {:?}", response_bytes.len(), response_bytes);

    let len = response_bytes.len();

    if len == 4 { // Must be an error code
        // Error codes are represented as negative i32
        let code = LittleEndian::read_i32(response_bytes);
        bail!(ErrorKind::TcpErrorCode(-code));
    } else if len < 24 {
        bail!(ErrorKind::BadTcpMessage(len));
    }

    let encrypted_data_len = S::encrypted_data_len(len);
    let seed = S::Seed::new(encrypted_data_len);

    serde_mtproto::from_bytes_seed(seed, response_bytes, &[]).map_err(Into::into)
}

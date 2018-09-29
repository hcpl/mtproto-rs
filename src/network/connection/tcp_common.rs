use std::fmt;

use byteorder::{ByteOrder, LittleEndian};
use serde::de::DeserializeOwned;
use serde_mtproto;

use ::error::{self, ErrorKind};
use ::tl::TLObject;
use ::tl::message::{MessageCommon, RawMessageSeedCommon};
use ::network::state::State;


pub(crate) fn parse_response<U, N>(state: &State, response_bytes: &[u8]) -> error::Result<N>
    where U: fmt::Debug + DeserializeOwned + TLObject,
          N: MessageCommon<U>,
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

    let encrypted_data_len = N::encrypted_data_len(len);

    macro_rules! deserialize_response {
        ($vnames:expr) => {{
            serde_mtproto::from_bytes_seed(N::RawSeed::new(encrypted_data_len), response_bytes, $vnames)
                .map_err(Into::into)
                .and_then(|raw| N::from_raw(raw, state.auth_raw_key(), state.version, $vnames))
        }};
    }

    if let Some(variant_names) = U::all_enum_variant_names() {
        // FIXME: Lossy error management
        for vname in variant_names {
            if let Ok(msg) = deserialize_response!(&[vname]) {
                return Ok(msg);
            }
        }

        bail!(ErrorKind::BadTcpMessage(len))
    } else {
        deserialize_response!(&[])
    }
}


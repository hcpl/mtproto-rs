use std::fmt;
use std::marker::PhantomData;

use serde::de::{self, Deserialize, Deserializer, DeserializeOwned};
use serde_mtproto::Identifiable;

use ::schema;
use ::tl::gzip_packed::GzipPacked;


const RPC_RESULT_ID: u32 = 0xf35c6d01;

#[derive(Debug)]
pub enum RpcResult<T> {
    Plain {
        req_msg_id: i64,
        body: T,
    },
    GzipPacked {
        req_msg_id: i64,
        body: GzipPacked<T>,
    },
    Error {
        req_msg_id: i64,
        error: schema::RpcError,
    },
}

impl<'de, T: DeserializeOwned> Deserialize<'de> for RpcResult<T> {
    fn deserialize<D>(deserializer: D) -> Result<RpcResult<T>, D::Error>
        where D: Deserializer<'de>
    {
        struct RpcResultVisitor<T>(PhantomData<T>);

        impl<'de, T: DeserializeOwned> de::Visitor<'de> for RpcResultVisitor<T> {
            type Value = RpcResult<T>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an RPC result")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<RpcResult<T>, A::Error>
                where A: de::SeqAccess<'de>,
            {
                // TODO: use `seq.size_hint()`?

                let req_msg_id = seq.next_element()?.unwrap();  // FIXME

                if let Some(rpc_error) = seq.next_element()? {
                    Ok(RpcResult::Error { req_msg_id, error: rpc_error })
                } else if let Some(gzip_packed) = seq.next_element()? {
                    Ok(RpcResult::GzipPacked { req_msg_id, body: gzip_packed })
                } else if let Some(body) = seq.next_element()? {
                    Ok(RpcResult::Plain { req_msg_id, body })
                } else {
                    unimplemented!();  // FIXME
                }
            }
        }

        // TODO: change to `deserialize_map` after testing under `serde_json`?
        deserializer.deserialize_seq(RpcResultVisitor(PhantomData))
    }
}

impl<T> Identifiable for RpcResult<T> {
    fn all_type_ids() -> &'static [u32] {
        &[RPC_RESULT_ID]
    }

    fn all_enum_variant_names() -> Option<&'static [&'static str]> {
        Some(&["Plain", "GzipPacked", "Error"])
    }

    fn type_id(&self) -> u32 {
        RPC_RESULT_ID
    }

    fn enum_variant_id(&self) -> Option<&'static str> {
        let variant_id = match *self {
            RpcResult::Plain { .. } => "Plain",
            RpcResult::GzipPacked { .. } => "GzipPacked",
            RpcResult::Error { .. } => "Error",
        };

        Some(variant_id)
    }
}

use erased_serde::Serialize as ErasedSerialize;

use crate::tl::dynamic::TLObject;


pub trait RpcFunction: ErasedSerialize {
    type Reply: TLObject + 'static;
}

use erased_serde::Serialize as ErasedSerialize;

use ::tl::dynamic::TLObject;


pub trait RpcFunction: ErasedSerialize {
    type Reply: TLObject + 'static;
}

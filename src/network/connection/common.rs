use std::fmt;

use futures::Future;
use serde::ser::Serialize;
use serde::de::DeserializeOwned;

use ::error;
use ::tl::TLObject;
use ::network::state::{MessagePurpose, State};


pub trait Connection: Send + Sized + 'static {
    type Addr;

    fn new(addr: Self::Addr) -> Box<Future<Item = Self, Error = error::Error> + Send>;

    fn request_plain<T, U>(self, state: State, request_data: T, purpose: MessagePurpose)
        -> Box<Future<Item = (Self, State, U), Error = error::Error> + Send>
        where T: fmt::Debug + Serialize + TLObject + Send,
              U: fmt::Debug + DeserializeOwned + TLObject + Send;

    fn request<T, U>(self, state: State, request_data: T, purpose: MessagePurpose)
        -> Box<Future<Item = (Self, State, U), Error = error::Error> + Send>
        where T: fmt::Debug + Serialize + TLObject + Send,
              U: fmt::Debug + DeserializeOwned + TLObject + Send;
}

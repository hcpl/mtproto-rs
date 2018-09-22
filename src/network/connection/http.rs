use std::fmt;
use std::str;

use futures::{self, Future, IntoFuture, Stream};
use hyper;
use select::document::Document;
use select::predicate::Name;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_mtproto::{self, MtProtoSized};

use ::error::{self, ErrorKind};
use ::network::connection::common::Connection;
use ::network::connection::server::HTTP_SERVER_ADDRS;
use ::network::state::{MessagePurpose, State};
use ::tl::TLObject;
use ::tl::message::{Message, MessageCommon, MessagePlain, RawMessageSeedCommon};


pub struct ConnectionHttp {
    client: hyper::Client<hyper::client::HttpConnector>,
    server_addr: hyper::Uri,
}

impl ConnectionHttp {
    pub fn new(server_addr: hyper::Uri) -> Self {
        info!("New HTTP connection to {}", &server_addr);
        Self { client: hyper::Client::new(), server_addr }
    }

    pub fn with_default_server() -> Self {
        Self::new(HTTP_SERVER_ADDRS[0].clone())
    }

    pub fn request_plain<T, U>(self, state: State, request_data: T, purpose: MessagePurpose)
        -> Box<Future<Item = (Self, State, U), Error = error::Error> + Send>
        where T: fmt::Debug + Serialize + TLObject + Send,
              U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_request::<T, U, MessagePlain<T>, MessagePlain<U>>(state, request_data, purpose)
    }

    pub fn request<T, U>(self, state: State, request_data: T, purpose: MessagePurpose)
        -> Box<Future<Item = (Self, State, U), Error = error::Error> + Send>
        where T: fmt::Debug + Serialize + TLObject + Send,
              U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.impl_request::<T, U, Message<T>, Message<U>>(state, request_data, purpose)
    }

    fn impl_request<T, U, M, N>(self, mut state: State, request_data: T, purpose: MessagePurpose)
        -> Box<Future<Item = (Self, State, U), Error = error::Error> + Send>
        where T: fmt::Debug + Serialize + TLObject + Send,
              U: fmt::Debug + DeserializeOwned + TLObject + Send,
              M: MessageCommon<T>,
              N: MessageCommon<U> + 'static,
    {
        let request_message = tryf!(state.create_message::<T, M>(request_data, purpose));
        debug!("Message to send: {:#?}", request_message);

        let http_request = tryf!(create_http_request(&state, request_message, &self.server_addr));
        debug!("HTTP request: {:?}", &http_request);

        // Split up parts, to be reassembled afterwards
        let Self { client, server_addr } = self;

        let request_future = client
            .request(http_request)
            .and_then(|res| res.into_body().concat2())
            .map(|data| data.to_vec())
            .map_err(|err| err.into());

        Box::new(request_future.and_then(move |response_bytes| {
            parse_response::<U, N>(&state, &response_bytes)
                .into_future()
                .and_then(move |msg| {
                    let conn = Self { client, server_addr };

                    futures::future::ok((conn, state, msg.into_body()))
                })
        }))
    }
}

impl Connection for ConnectionHttp {
    type Addr = hyper::Uri;

    fn request_plain<T, U>(self, state: State, request_data: T, purpose: MessagePurpose)
        -> Box<Future<Item = (Self, State, U), Error = error::Error> + Send>
        where T: fmt::Debug + Serialize + TLObject + Send,
              U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.request_plain(state, request_data, purpose)
    }

    fn request<T, U>(self, state: State, request_data: T, purpose: MessagePurpose)
        -> Box<Future<Item = (Self, State, U), Error = error::Error> + Send>
        where T: fmt::Debug + Serialize + TLObject + Send,
              U: fmt::Debug + DeserializeOwned + TLObject + Send,
    {
        self.request(state, request_data, purpose)
    }
}


fn create_http_request<T, M>(state: &State, request_message: M, server_addr: &hyper::Uri)
    -> error::Result<hyper::Request<hyper::Body>>
    where T: fmt::Debug + Serialize + TLObject,
          M: MessageCommon<T>,
{
    let raw_message = request_message.to_raw(state.auth_raw_key(), state.version)?;
    let serialized_message = serde_mtproto::to_bytes(&raw_message)?;

    // Here we do mean to unwrap since it should fail if something goes wrong anyway
    assert_eq!(raw_message.size_hint().unwrap(), serialized_message.len());

    hyper::Request::post(server_addr)
        .header(hyper::header::CONNECTION, "keep-alive")
        .header(hyper::header::CONTENT_LENGTH, serialized_message.len())
        .body(serialized_message.into())
        .map_err(Into::into)
}

fn parse_response<U, N>(state: &State, response_bytes: &[u8]) -> error::Result<N>
    where U: fmt::Debug + DeserializeOwned + TLObject,
          N: MessageCommon<U>,
{
    debug!("Response bytes: {:?}", &response_bytes);

    if let Ok(response_str) = str::from_utf8(response_bytes) {
        let response_str = response_str.trim();
        let str_len = response_str.len();

        if str_len >= 7 && &response_str[0..6] == "<html>" && &response_str[str_len-7..] == "</html>" {
            let response_str = str::from_utf8(response_bytes)?;
            let doc = Document::from(response_str);
            info!("HTML error response:\n{}", response_str);

            let error_text = match doc.find(Name("h1")).next() {
                Some(elem) => elem.text(),
                None => bail!(ErrorKind::UnknownHtmlErrorStructure(response_str.to_owned())),
            };

            bail!(ErrorKind::HtmlErrorText(error_text));
        }
    }

    let len = response_bytes.len();

    if len < 24 {
        bail!(ErrorKind::BadHtmlMessage(len));
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

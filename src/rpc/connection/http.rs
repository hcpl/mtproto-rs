use std::fmt;
use std::str;

use futures::{self, Future, IntoFuture, Stream};
use hyper::{self, Client as HttpClient, Method as HttpMethod, Request as HttpRequest};
use hyper::client::HttpConnector;
use hyper::header;
use select::document::Document;
use select::predicate::Name;
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use serde_mtproto::{self, MtProtoSized};

use error::{self, ErrorKind};
use rpc::{Message, MessageType, Session};
use tl::TLObject;

use super::HTTP_SERVER_ADDRS;


#[derive(Debug)]
pub struct HttpConnection {
    server_addr: hyper::Uri,
}

impl Default for HttpConnection {
    fn default() -> HttpConnection {
        HttpConnection {
            server_addr: HTTP_SERVER_ADDRS[0].clone(),
        }
    }
}

impl HttpConnection {
    pub fn new(server_addr: hyper::Uri) -> HttpConnection {
        HttpConnection { server_addr }
    }

    pub fn request<T, U>(&mut self,
                         http_client: HttpClient<HttpConnector>,
                         mut session: Session,
                         request_data: T,
                         request_message_type: MessageType,
                         response_message_type: MessageType)
        -> Box<Future<Item = (HttpClient<HttpConnector>, Option<U>, Session), Error = error::Error>>
        where T: fmt::Debug + Serialize + TLObject,
              U: fmt::Debug + DeserializeOwned + TLObject,
    {
        let request_message = tryf!(create_message(&mut session, request_data, request_message_type));

        let http_request = tryf!(self.create_http_request(request_message));
        debug!("HTTP request: {:?}", &http_request);

        let request_future = http_client
            .request(http_request)
            .and_then(|res| res.body().concat2())
            .map(|data| data.to_vec())
            .map_err(|err| err.into());

        Box::new(request_future.and_then(move |response_bytes| {
            parse_response::<U>(&session, &response_bytes, response_message_type)
                .into_future()
                .map(move |msg| (http_client, msg.into_body(response_message_type), session))
        }))
    }

    fn create_http_request<T>(&mut self, request_message: Message<T>) -> error::Result<HttpRequest>
        where T: fmt::Debug + Serialize + TLObject
    {
        let serialized_message = serde_mtproto::to_bytes(&request_message)?;

        // Here we do mean to unwrap since it should fail if something goes wrong anyway
        assert_eq!(request_message.size_hint().unwrap(), serialized_message.len());

        let mut request = HttpRequest::new(HttpMethod::Post, self.server_addr.clone());

        {
            let headers = request.headers_mut();
            headers.set(header::Connection::keep_alive());
            headers.set(header::ContentLength(serialized_message.len() as u64));
        }

        request.set_body(serialized_message);

        Ok(request)
    }
}


fn create_message<T>(session: &mut Session,
                     data: T,
                     message_type: MessageType)
                    -> error::Result<Message<T>>
    where T: fmt::Debug + TLObject
{
    let message = match message_type {
        MessageType::PlainText => session.create_plain_text_message(data)?,
        MessageType::Encrypted => session.create_encrypted_message_no_acks(data)?.unwrap(), // FIXME
    };
    debug!("Message to send: {:#?}", &message);

    Ok(message)
}

fn parse_response<U>(session: &Session,
                     response_bytes: &[u8],
                     message_type: MessageType)
                    -> error::Result<Message<U>>
    where U: fmt::Debug + DeserializeOwned
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

    let encrypted_data_len = match message_type {
        MessageType::PlainText => None,
        MessageType::Encrypted => Some((len - 24) as u32),
    };

    let response_message = session.process_message(&response_bytes, encrypted_data_len)?;

    Ok(response_message)
}

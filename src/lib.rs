use futures_util::Future;
use jwks_client_rs::source::WebSource;
use jwks_client_rs::{JsonWebKey, JwksClient as JwksClientRS, JwksClientError};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use tracing::error;

use actix_web::{
    error::ErrorBadRequest,
    http::{header, StatusCode},
    web::Data,
    Error as ActixError, FromRequest, HttpResponse, HttpResponseBuilder, ResponseError,
};

// use futures_util::Future;

// use josekit::{
//     jwk::{Jwk, JwkSet},
//     jws::RS256,
//     jwt,
//     jwt::JwtPayloadValidator,
// };
// use parking_lot::RwLock;
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("reqwest: {0}")]
    Reqwest(reqwest::Error),

    #[error("jwks_client: {0}")]
    JwksClient(JwksClientError),

    #[error("{0}")]
    Unknown(String),
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Reqwest(e)
    }
}

impl From<JwksClientError> for Error {
    fn from(e: JwksClientError) -> Self {
        Error::JwksClient(e)
    }
}

impl ResponseError for Error {
    fn status_code(&self) -> StatusCode {
        StatusCode::INTERNAL_SERVER_ERROR
    }

    fn error_response(&self) -> HttpResponse {
        let mut res = HttpResponseBuilder::new(self.status_code());

        error!("{}", self);

        res.json(
            serde_json::json!({"code": self.status_code().as_u16(), "message": self.to_string()}),
        )
    }
}

///
/// ```rust
///
/// use actix_jwks::JwksClient;
///
/// let jwks_client = JwksClient::new("http://127.0.0.1:4456/.well-known/jwks.json").unwrap();
/// ```
#[derive(Clone)]
pub struct JwksClient {
    inner: JwksClientRS<WebSource>,
}

impl JwksClient {
    pub fn new<U: Into<String>>(url: U) -> Result<Self, Error> {
        let source: WebSource = WebSource::builder()
            .build(Url::parse(&url.into()).map_err(|e| Error::Unknown(e.to_string()))?)?;
        let client = JwksClientRS::builder().build(source);

        Ok(Self { inner: client })
    }

    pub async fn get(&self, kid: &str) -> Result<JsonWebKey, JwksClientError> {
        self.inner.get(kid).await
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    aud: String, // Optional. Audience
    exp: usize, // Required (validate_exp defaults to true in validation). Expiration time (as UTC timestamp)
    iat: usize, // Optional. Issued at (as UTC timestamp)
    iss: String, // Optional. Issuer
    nbf: usize, // Optional. Not Before (as UTC timestamp)
    sub: String, // Optional. Subject (whom token refers to)
}

pub struct JwtPayload {
    pub subject: String,
    pub token: String,
    pub payload: Claims,
}

impl FromRequest for JwtPayload {
    type Error = ActixError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(
        req: &actix_web::HttpRequest,
        _payload: &mut actix_web::dev::Payload,
    ) -> Self::Future {
        let req = req.clone();
        let client = req
            .app_data::<Data<JwksClient>>()
            .expect("JwksClient not found in app data")
            .clone();

        Box::pin(async move {
            let token = match req
                .headers()
                .get(header::AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
            {
                Some(value) => value.replace("Bearer ", ""),
                _ => return Err(ErrorBadRequest("authorization is missing from header")),
            };

            let payload = client
                .inner
                .decode::<Claims>(&token, &[] as &[String])
                .await
                .map_err(Error::from)?;

            Ok(Self {
                subject: payload.sub.to_owned(),
                token,
                payload,
            })
        })
    }
}

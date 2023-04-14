use futures_util::Future;
use jwt::Jwt;
use keyset::KeyStore;
use serde_json::Value;
use std::{pin::Pin, sync::Arc};
use thiserror::Error as ThisError;
use tokio::sync::RwLock;
use tracing::error;

use actix_web::{
    error::ErrorBadRequest,
    http::{header, StatusCode},
    web::Data,
    Error as ActixError, FromRequest, HttpResponse, HttpResponseBuilder, ResponseError,
};

pub mod error;
pub mod jwt;
pub mod keyset;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("reqwest: {0}")]
    Reqwest(reqwest::Error),

    #[error("jwks_client: {0}")]
    Jwks(error::Error),

    #[error("{0}")]
    Unknown(String),
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Reqwest(e)
    }
}

impl From<error::Error> for Error {
    fn from(e: error::Error) -> Self {
        Error::Jwks(e)
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
/// let jwks_client = JwksClient::new("http://127.0.0.1:4456/.well-known/jwks.json").await.unwrap();
/// ```
#[derive(Clone)]
pub struct JwksClient {
    inner: Arc<RwLock<KeyStore>>,
    insecure: bool,
}

impl JwksClient {
    pub async fn new<U: Into<String>>(url: U) -> Result<Self, Error> {
        Self::build(Some(url)).await
    }

    pub async fn insecure() -> Result<Self, Error> {
        Self::build(None::<String>).await
    }

    pub async fn build<U: Into<String>>(url: Option<U>) -> Result<Self, Error> {
        match url {
            Some(url) => {
                let store = KeyStore::new_from(url.into()).await?;

                Ok(Self {
                    inner: Arc::new(RwLock::new(store)),
                    insecure: false,
                })
            }
            _ => {
                let store = KeyStore::new();

                Ok(Self {
                    inner: Arc::new(RwLock::new(store)),
                    insecure: true,
                })
            }
        }
    }

    pub async fn verify(&self, token: &str) -> Result<Jwt, error::Error> {
        let read = self.inner.read().await;

        if self.insecure {
            return read.decode(token);
        }

        if read.should_refresh().unwrap_or(false) {
            drop(read);

            let mut guard = self.inner.write().await;
            guard.load_keys().await?;

            drop(guard);
        }

        let read = self.inner.read().await;

        read.verify(token)
    }
}

pub struct JwtPayload {
    pub subject: String,
    pub token: String,
    pub payload: Value,
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

            let jwt = client.verify(&token).await.map_err(Error::from)?;
            let payload = jwt.payload();

            let sub = match payload.sub() {
                Some(sub) => sub,
                None => return Err(ErrorBadRequest("subject is missing from token")),
            };

            Ok(Self {
                subject: sub.to_owned(),
                token,
                payload: payload.json.clone(),
            })
        })
    }
}

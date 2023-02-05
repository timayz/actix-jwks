use std::sync::Arc;
use std::{pin::Pin, time::SystemTime};
use tracing::error;

use actix_web::{
    error::{ErrorBadRequest, ErrorUnauthorized},
    http::{header, StatusCode},
    web::Data,
    Error as ActixError, FromRequest, HttpMessage, HttpResponse, HttpResponseBuilder,
    ResponseError,
};

use futures_util::Future;

use josekit::{
    jwk::{Jwk, JwkSet},
    jws::RS256,
    jwt,
    jwt::JwtPayloadValidator,
};
use parking_lot::RwLock;
use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum Error {
    #[error("josekit: {0}")]
    JoseError(josekit::JoseError),

    #[error("jwt header key not found: {0}")]
    JwtHeaderKeyNotFound(String),

    #[error("jwk not found")]
    JwkNotFound,

    #[error("failed to fetch jwks keys")]
    FetchKeysFailed(StatusCode, String),
}

impl From<josekit::JoseError> for Error {
    fn from(e: josekit::JoseError) -> Self {
        Error::JoseError(e)
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
/// let jwks_client = JwksClient::new("http://127.0.0.1:4456/.well-known/jwks.json");
/// ```
#[derive(Debug, Clone)]
pub struct JwksClient {
    url: String,
    jwk_set: Arc<RwLock<JwkSet>>,
}

impl JwksClient {
    pub fn new<U: Into<String>>(url: U) -> Self {
        Self {
            url: url.into(),
            jwk_set: Arc::new(RwLock::new(JwkSet::new())),
        }
    }

    pub async fn get(&self, input: &str) -> Result<Jwk, Error> {
        let header = jwt::decode_header(input)?;

        let key_id = match header.claim("kid").and_then(|key_id| key_id.as_str()) {
            Some(key_id) => key_id,
            _ => return Err(Error::JwtHeaderKeyNotFound("kid".to_owned())),
        };

        let alg = match header.claim("alg").and_then(|key_id| key_id.as_str()) {
            Some(alg) => alg,
            _ => return Err(Error::JwtHeaderKeyNotFound("alg".to_owned())),
        };

        {
            let jwk_set = self.jwk_set.read();

            for jwk in jwk_set.get(key_id.to_string().as_ref()) {
                if jwk.algorithm().unwrap_or("") == alg {
                    return Ok(jwk.clone());
                }
            }
        }

        let fetched_jwk_set = self.fetch_keys().await?;

        for jwk in fetched_jwk_set.get(key_id) {
            if jwk.algorithm().unwrap_or("") != alg {
                continue;
            }

            {
                let mut jwk_set = self.jwk_set.write();
                *jwk_set = fetched_jwk_set.clone();
            }

            return Ok(jwk.clone());
        }

        Err(Error::JwkNotFound)
    }

    async fn fetch_keys(&self) -> Result<JwkSet, Error> {
        let client = awc::Client::default();

        let req = client.get(&self.url);
        let mut res = req.send().await.unwrap();
        let body = match res.status() {
            StatusCode::OK => res.body().await.unwrap(),
            _ => return Err(Error::FetchKeysFailed(res.status(), self.url.to_owned())),
        };

        Ok(JwkSet::from_bytes(&body)?)
    }
}

pub struct JwtPayload {
    pub subject: String,
    pub token: String,
    pub payload: jwt::JwtPayload,
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

            println!("yes");
            let jwk = client.get(&token).await?;
            Err(ErrorUnauthorized("unauthorized"))
            // let verifier = RS256.verifier_from_jwk(&jwk).map_err(Error::from)?;
            // let (payload, _) = jwt::decode_with_verifier(&token, &verifier).map_err(Error::from)?;

            // let mut validator = JwtPayloadValidator::new();
            // validator.set_base_time(SystemTime::now());

            // if validator.validate(&payload).is_err() {
            //     return Err(ErrorUnauthorized("unauthorized"));
            // }

            // match (validator.validate(&payload), payload.subject()) {
            //     (Ok(_), Some(sub)) => {
            //         req.extensions_mut().insert(payload.clone());

            //         Ok(Self {
            //             subject: sub.into(),
            //             token,
            //             payload,
            //         })
            //     }
            //     _ => Err(ErrorUnauthorized("unauthorized")),
            // }
        })
    }
}

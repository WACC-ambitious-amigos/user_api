use actix_http::{http::header, ResponseBuilder};
use actix_web::{
    dev::Payload, error, http::StatusCode, Error, FromRequest, HttpRequest, HttpResponse,
};
use log::debug;
use derive_more::{Display, Error};
use futures::future;
use serde::{Deserialize, Serialize};

use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

lazy_static::lazy_static! {
    static ref SECRET_KEY: String = std::env::var("JWT_SECRET_KEY").unwrap();
    static ref CLAIM_ISSUER: String = std::env::var("JWT_ISSUER").unwrap();
    static ref EXPIRATION_TIME: i64 = std::env::var("JWT_EXPIRE_TIME").unwrap().parse::<i64>().unwrap();
}


#[derive(Debug, Display, Error)]
pub enum AuthError {
    #[display(fmt = "unauthorized")]
    UnauthorizedError,

    #[display(fmt = "bad request")]
    BadRequestError,
}

impl error::ResponseError for AuthError {
    fn error_response(&self) -> HttpResponse {
        ResponseBuilder::new(self.status_code())
            .set_header(header::CONTENT_TYPE, "text/html; charset=utf-8")
            .body(self.to_string())
    }

    fn status_code(&self) -> StatusCode {
        match *self {
            AuthError::UnauthorizedError => StatusCode::UNAUTHORIZED,
            AuthError::BadRequestError => StatusCode::BAD_REQUEST,
        }
    }
}

pub struct User {
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    sub: String,
    exp: usize,
    iss: String,
    iat: usize,
}

impl FromRequest for User {
    type Error = Error;
    type Future = future::Ready<Result<Self, Self::Error>>;
    type Config = ();

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        if let Some(token) = req.headers().get("Authorization") {
            match verify_jwt(&token.to_str().unwrap(), SECRET_KEY.as_bytes()) {
                Ok(token_data) => {
                    let user = User {
                        username: token_data.sub,
                    };

                    future::ready(Ok(user))
                }
                Err(e) => future::ready(Err(e)),
            }
        } else {
            future::ready(Err(Error::from(AuthError::BadRequestError)))
        }
    }
}


pub fn verify_jwt(token: &str, secret_key: &[u8]) -> Result<Claims, Error> {
    let split_token = token.split_whitespace();
    let split_token_vec = &split_token.collect::<Vec<&str>>();

    // TODO: Check if the token size is correct, should be 2
    let mut current_index = 1;
    if split_token_vec.len() == 1 {
        current_index = 0;
    }

    let token_message = decode::<Claims>(
        &split_token_vec[current_index],
        // TODO: Get secret from config and randomly generate it
        &DecodingKey::from_secret(secret_key),
        &Validation::new(Algorithm::HS256),
    );
    match token_message {
        Ok(token_data) => Ok(token_data.claims),
        Err(error) => {
            debug!("error while verifying jwt token: {}", error);
            return Err(Error::from(AuthError::UnauthorizedError));
        },
    }
}

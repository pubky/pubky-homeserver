use thiserror::Error;
use url::Url;

#[derive(Error, Debug)]
#[error("{url} returned {status} {body}")]
pub struct HttpStatusError {
    pub status: u16,
    pub url: Url,
    pub body: String,
}

#[derive(Error, Debug)]
pub enum ApiError {
    #[error("user not found")]
    UserNotFound,

    #[error("missing or invalid admin password")]
    InvalidToken,

    #[error("invalid pubkey format")]
    InvalidPubkyFormat,

    #[error("invalid quota format")]
    InvalidQuotaFormat,
}

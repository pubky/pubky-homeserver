use std::io;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use pubky_common::{auth::jws::ClientId, capabilities::Capabilities, crypto::PublicKey};
use url::Url;

use super::DeepLinkParseError;

pub(super) fn parse_capabilities(url: &Url) -> Result<Capabilities, DeepLinkParseError> {
    required_query(url, "caps")?
        .parse()
        .map_err(|e| DeepLinkParseError::InvalidQueryParameter("caps", Box::new(e)))
}

pub(super) fn parse_relay(url: &Url) -> Result<Url, DeepLinkParseError> {
    Url::parse(&required_query(url, "relay")?)
        .map_err(|e| DeepLinkParseError::InvalidQueryParameter("relay", Box::new(e)))
}

pub(super) fn parse_secret(url: &Url) -> Result<[u8; 32], DeepLinkParseError> {
    let raw_secret = required_query(url, "secret")?;
    let secret = URL_SAFE_NO_PAD
        .decode(raw_secret.as_str())
        .map_err(|e| DeepLinkParseError::InvalidQueryParameter("secret", Box::new(e)))?;

    secret.try_into().map_err(|e: Vec<u8>| {
        let msg = format!("Expected 32 bytes, got {}", e.len());
        DeepLinkParseError::InvalidQueryParameter(
            "secret",
            Box::new(io::Error::new(io::ErrorKind::InvalidData, msg)),
        )
    })
}

pub(super) fn parse_homeserver(url: &Url) -> Result<PublicKey, DeepLinkParseError> {
    PublicKey::try_from_z32(&required_query(url, "hs")?)
        .map_err(|e| DeepLinkParseError::InvalidQueryParameter("hs", Box::new(e)))
}

pub(super) fn parse_client_id(url: &Url) -> Result<ClientId, DeepLinkParseError> {
    ClientId::new(&required_query(url, "cid")?)
        .map_err(|e| DeepLinkParseError::InvalidQueryParameter("cid", Box::new(e)))
}

pub(super) fn parse_client_pk(url: &Url) -> Result<PublicKey, DeepLinkParseError> {
    PublicKey::try_from_z32(&required_query(url, "cpk")?)
        .map_err(|e| DeepLinkParseError::InvalidQueryParameter("cpk", Box::new(e)))
}

pub(super) fn required_query(url: &Url, key: &'static str) -> Result<String, DeepLinkParseError> {
    optional_query(url, key).ok_or(DeepLinkParseError::MissingQueryParameter(key))
}

pub(super) fn optional_query(url: &Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(param_key, _)| param_key == key)
        .map(|(_, value)| value.to_string())
}

pub(super) fn append_signin_params(
    url: &mut Url,
    capabilities: &Capabilities,
    relay: &Url,
    secret: &[u8; 32],
) {
    url.query_pairs_mut()
        .append_pair("caps", &capabilities.to_string())
        .append_pair("relay", relay.as_str())
        .append_pair("secret", &URL_SAFE_NO_PAD.encode(secret));
}

pub(super) fn append_signup_params(
    url: &mut Url,
    capabilities: &Capabilities,
    relay: &Url,
    secret: &[u8; 32],
    homeserver: &PublicKey,
    signup_token: Option<&str>,
) {
    append_signin_params(url, capabilities, relay, secret);
    let mut query = url.query_pairs_mut();
    query.append_pair("hs", &homeserver.z32());
    if let Some(signup_token) = signup_token {
        query.append_pair("st", signup_token);
    }
}

pub(super) fn append_direct_signup_params(
    url: &mut Url,
    homeserver: &PublicKey,
    signup_token: Option<&str>,
) {
    let mut query = url.query_pairs_mut();
    query.append_pair("hs", &homeserver.z32());
    if let Some(signup_token) = signup_token {
        query.append_pair("st", signup_token);
    }
}

pub(super) fn append_grant_params(url: &mut Url, client_id: &ClientId, client_pk: &PublicKey) {
    url.query_pairs_mut()
        .append_pair("cid", &client_id.to_string())
        .append_pair("cpk", &client_pk.z32());
}

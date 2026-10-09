use std::io;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use pubky_common::{auth::jws::ClientId, capabilities::Capabilities, crypto::PublicKey};
use url::Url;

use super::{DeepLinkParseError, GrantApprovalFormat, GrantRelayChannel};

pub(super) fn parse_grant_approval_format(
    url: &Url,
) -> Result<GrantApprovalFormat, DeepLinkParseError> {
    let mut values = url
        .query_pairs()
        .filter(|(key, _)| key == "af")
        .map(|(_, value)| value);
    match (values.next(), values.next()) {
        (None, None) => Ok(GrantApprovalFormat::BareGrant),
        (Some(value), None) if value == "v1" => Ok(GrantApprovalFormat::SignedApprovalV1),
        _ => Err(DeepLinkParseError::InvalidQueryParameter(
            "af",
            Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                "expected one af=v1 parameter, or none for a bare grant",
            )),
        )),
    }
}

pub(super) fn append_grant_approval_format(url: &mut Url, format: GrantApprovalFormat) {
    if format == GrantApprovalFormat::SignedApprovalV1 {
        url.query_pairs_mut().append_pair("af", "v1");
    }
}

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
    decode_channel_key(&required_query(url, "secret")?, "secret")
}

fn decode_channel_key(raw: &str, name: &'static str) -> Result<[u8; 32], DeepLinkParseError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|error| DeepLinkParseError::InvalidQueryParameter(name, Box::new(error)))?;
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        DeepLinkParseError::InvalidQueryParameter(
            name,
            Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected 32 bytes, got {}", bytes.len()),
            )),
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

pub(super) fn parse_grant_relay_channel(
    url: &Url,
    approval_format: GrantApprovalFormat,
) -> Result<GrantRelayChannel, DeepLinkParseError> {
    let ephemeral_public_key = parse_ephemeral_public_key(url)?;
    let shared_secret = optional_query(url, "secret")
        .map(|secret| decode_channel_key(&secret, "secret"))
        .transpose()?;

    match (ephemeral_public_key, shared_secret, approval_format) {
        (Some(ephemeral_public_key), None, _) => Ok(GrantRelayChannel::Hpke {
            ephemeral_public_key,
        }),
        (Some(_), Some(_), _) => Err(DeepLinkParseError::InvalidQueryParameter(
            "secret",
            Box::new(io::Error::new(
                io::ErrorKind::InvalidInput,
                "secret must be omitted when epk is present",
            )),
        )),
        (None, _, GrantApprovalFormat::SignedApprovalV1) => Err(missing_ephemeral_public_key()),
        (None, Some(secret), GrantApprovalFormat::BareGrant) => {
            Ok(GrantRelayChannel::SharedSecret(secret))
        }
        (None, None, GrantApprovalFormat::BareGrant) => {
            Err(DeepLinkParseError::MissingQueryParameter("secret"))
        }
    }
}

fn missing_ephemeral_public_key() -> DeepLinkParseError {
    DeepLinkParseError::InvalidQueryParameter(
        "epk",
        Box::new(io::Error::new(
            io::ErrorKind::InvalidInput,
            "af=v1 requires one epk parameter",
        )),
    )
}

fn parse_ephemeral_public_key(url: &Url) -> Result<Option<[u8; 32]>, DeepLinkParseError> {
    optional_query(url, "epk")
        .map(|encoded| decode_channel_key(&encoded, "epk"))
        .transpose()
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
    append_relay_params(url, capabilities, relay);
    url.query_pairs_mut()
        .append_pair("secret", &URL_SAFE_NO_PAD.encode(secret));
}

pub(super) fn append_relay_params(url: &mut Url, capabilities: &Capabilities, relay: &Url) {
    url.query_pairs_mut()
        .append_pair("caps", &capabilities.to_string())
        .append_pair("relay", relay.as_str());
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
    append_signup_details(url, homeserver, signup_token);
}

pub(super) fn append_signup_details(
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

pub(super) fn append_grant_relay_channel(url: &mut Url, channel: GrantRelayChannel) {
    match channel {
        GrantRelayChannel::SharedSecret(secret) => {
            url.query_pairs_mut()
                .append_pair("secret", &URL_SAFE_NO_PAD.encode(secret));
        }
        GrantRelayChannel::Hpke {
            ephemeral_public_key,
        } => {
            url.query_pairs_mut()
                .append_pair("epk", &URL_SAFE_NO_PAD.encode(ephemeral_public_key));
        }
    }
}

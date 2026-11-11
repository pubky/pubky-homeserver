use std::{borrow::Cow, io};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use pubky_common::{auth::jws::ClientId, capabilities::Capabilities, crypto::PublicKey};
use url::Url;

use super::{DeepLinkParseError, GrantApprovalFormat, GrantRelayChannel};

pub(super) fn parse_grant_approval_format(
    url: &Url,
) -> Result<GrantApprovalFormat, DeepLinkParseError> {
    match optional_unique_query(url, "af")?.as_deref() {
        None => Ok(GrantApprovalFormat::BareGrant),
        Some("v1") => Ok(GrantApprovalFormat::SignedApprovalV1),
        Some(_) => Err(invalid_query_input(
            "af",
            "expected one af=v1 parameter, or none for a bare grant",
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
    parse_required_public_key(url, "hs")
}

pub(super) fn parse_client_id(url: &Url) -> Result<ClientId, DeepLinkParseError> {
    ClientId::new(&required_query(url, "cid")?)
        .map_err(|e| DeepLinkParseError::InvalidQueryParameter("cid", Box::new(e)))
}

pub(super) fn parse_client_pk(url: &Url) -> Result<PublicKey, DeepLinkParseError> {
    parse_required_public_key(url, "cpk")
}

fn parse_required_public_key(
    url: &Url,
    name: &'static str,
) -> Result<PublicKey, DeepLinkParseError> {
    PublicKey::try_from_z32(&required_query(url, name)?)
        .map_err(|e| DeepLinkParseError::InvalidQueryParameter(name, Box::new(e)))
}

pub(super) fn parse_expected_signer(url: &Url) -> Result<Option<PublicKey>, DeepLinkParseError> {
    let Some(value) = optional_unique_query(url, "spk")? else {
        return Ok(None);
    };
    let key = PublicKey::try_from_z32(&value)
        .map_err(|error| DeepLinkParseError::InvalidQueryParameter("spk", Box::new(error)))?;

    // Pkarr also accepts prefixes, URLs and noncanonical encodings, but the
    // spk wire format requires a bare, canonical z32 key.
    if key.z32() != value {
        return Err(invalid_query_input(
            "spk",
            "expected a bare, canonical z-base-32 public key",
        ));
    }
    Ok(Some(key))
}

pub(super) fn append_expected_signer(url: &mut Url, expected_signer: Option<&PublicKey>) {
    if let Some(expected_signer) = expected_signer {
        url.query_pairs_mut()
            .append_pair("spk", &expected_signer.z32());
    }
}

pub(super) fn parse_grant_relay_channel(
    url: &Url,
    approval_format: GrantApprovalFormat,
) -> Result<GrantRelayChannel, DeepLinkParseError> {
    let ephemeral_public_key = parse_optional_channel_key(url, "epk")?;
    let shared_secret = parse_optional_channel_key(url, "secret")?;

    match (ephemeral_public_key, shared_secret, approval_format) {
        (Some(ephemeral_public_key), None, _) => Ok(GrantRelayChannel::Hpke {
            ephemeral_public_key,
        }),
        (Some(_), Some(_), _) => Err(invalid_query_input(
            "secret",
            "secret must be omitted when epk is present",
        )),
        (None, _, GrantApprovalFormat::SignedApprovalV1) => Err(invalid_query_input(
            "epk",
            "af=v1 requires one epk parameter",
        )),
        (None, Some(secret), GrantApprovalFormat::BareGrant) => {
            Ok(GrantRelayChannel::SharedSecret(secret))
        }
        (None, None, GrantApprovalFormat::BareGrant) => {
            Err(DeepLinkParseError::MissingQueryParameter("secret"))
        }
    }
}

pub(super) fn parse_optional_channel_key(
    url: &Url,
    name: &'static str,
) -> Result<Option<[u8; 32]>, DeepLinkParseError> {
    optional_query(url, name)
        .map(|encoded| decode_channel_key(&encoded, name))
        .transpose()
}

pub(super) fn required_query(url: &Url, key: &'static str) -> Result<String, DeepLinkParseError> {
    optional_query(url, key).ok_or(DeepLinkParseError::MissingQueryParameter(key))
}

/// Returns the first value, preserving legacy handling of repeated parameters.
pub(super) fn optional_query(url: &Url, key: &str) -> Option<String> {
    url.query_pairs()
        .find(|(param_key, _)| param_key == key)
        .map(|(_, value)| value.into_owned())
}

/// Returns the value if present and rejects repeated parameter names.
fn optional_unique_query(
    url: &Url,
    key: &'static str,
) -> Result<Option<String>, DeepLinkParseError> {
    let mut values = url
        .query_pairs()
        .filter(|(param_key, _)| param_key == key)
        .map(|(_, value)| value);
    let value = values.next();
    if values.next().is_some() {
        return Err(invalid_query_input(
            key,
            format!("expected at most one {key} parameter"),
        ));
    }
    Ok(value.map(Cow::into_owned))
}

pub(super) fn invalid_query_input(
    name: &'static str,
    message: impl Into<String>,
) -> DeepLinkParseError {
    DeepLinkParseError::InvalidQueryParameter(
        name,
        Box::new(io::Error::new(io::ErrorKind::InvalidInput, message.into())),
    )
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

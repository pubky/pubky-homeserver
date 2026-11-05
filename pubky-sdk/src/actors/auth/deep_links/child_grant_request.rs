use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use pubky_common::{
    auth::{grant::is_exact_callback, jws::ClientId},
    capabilities::Capabilities,
    crypto::PublicKey,
};
use url::{Url, form_urlencoded};

use super::{
    DeepLinkParseError,
    query_params::{
        invalid_parameter, parse_capabilities, parse_client_id, parse_client_pk,
        parse_ephemeral_public_key, required_query,
    },
};
use crate::errors::RedirectDenial;

const MAX_STATE_LENGTH: usize = 128;

/// An app's redirect request for a child grant, as received by the parent holder.
///
/// The holder should check [`Self::callback`] and [`Self::capabilities`] against
/// its own app catalog before issuing a child grant. Every field comes from the
/// request URL and is untrusted until then.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChildGrantRequest {
    capabilities: Capabilities,
    callback: ClientId,
    client_pk: PublicKey,
    ephemeral_public_key: [u8; 32],
    state: String,
}

impl ChildGrantRequest {
    pub(crate) const fn new(
        capabilities: Capabilities,
        callback: ClientId,
        client_pk: PublicKey,
        ephemeral_public_key: [u8; 32],
        state: String,
    ) -> Self {
        Self {
            capabilities,
            callback,
            client_pk,
            ephemeral_public_key,
            state,
        }
    }

    /// Parse the request from the URL the app redirected to.
    ///
    /// # Errors
    /// Rejects missing or malformed parameters and callbacks that aren't exact
    /// HTTPS URLs.
    pub fn parse(url: &Url) -> Result<Self, DeepLinkParseError> {
        let callback = parse_client_id(url)?;
        if !is_exact_callback(&callback) {
            return Err(invalid_parameter(
                "cid",
                "child grants require an exact HTTPS callback URL",
            ));
        }
        let state = required_query(url, "state")?;
        if state.is_empty() || state.len() > MAX_STATE_LENGTH {
            return Err(invalid_parameter(
                "state",
                "state must be 1 to 128 bytes long",
            ));
        }
        Ok(Self::new(
            parse_capabilities(url)?,
            callback,
            parse_client_pk(url)?,
            parse_ephemeral_public_key(url)?
                .ok_or(DeepLinkParseError::MissingQueryParameter("epk"))?,
            state,
        ))
    }

    /// Capabilities requested by the app.
    pub const fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    /// The app's exact callback URL, which becomes the child's `client_id`.
    #[must_use]
    pub const fn callback(&self) -> &ClientId {
        &self.callback
    }

    /// The app's public key, bound by the child's `cnf` claim.
    #[must_use]
    pub const fn client_pk(&self) -> &PublicKey {
        &self.client_pk
    }

    /// Temporary HPKE public key the approval is encrypted to.
    #[must_use]
    pub const fn ephemeral_public_key(&self) -> &[u8; 32] {
        &self.ephemeral_public_key
    }

    /// Single-use value that binds the response to this request.
    #[must_use]
    pub fn state(&self) -> &str {
        &self.state
    }

    /// Build the callback URL that returns an encrypted approval to the app.
    ///
    /// The fragment isn't sent to servers, but it is visible to the app's page.
    pub(crate) fn approved_url(&self, sealed_approval: &[u8]) -> Url {
        self.callback_url("approval", &URL_SAFE_NO_PAD.encode(sealed_approval))
    }

    /// Build the callback URL that tells the app no child grant was issued.
    #[must_use]
    pub fn declined_url(&self, reason: RedirectDenial) -> Url {
        self.callback_url("error", reason.as_str())
    }

    fn callback_url(&self, key: &str, value: &str) -> Url {
        let mut url =
            Url::parse(self.callback.as_str()).expect("invariant: the callback was validated");
        let fragment = form_urlencoded::Serializer::new(String::new())
            .append_pair(key, value)
            .append_pair("state", &self.state)
            .finish();
        url.set_fragment(Some(&fragment));
        url
    }
}

#[cfg(test)]
mod tests {
    use pubky_common::crypto::Keypair;

    use super::*;

    const CALLBACK: &str = "https://chat.example/auth/callback";

    fn request() -> ChildGrantRequest {
        ChildGrantRequest::new(
            "/pub/chat/:rwe".parse().unwrap(),
            ClientId::new(CALLBACK).unwrap(),
            Keypair::random().public_key(),
            [7; 32],
            "state-1".into(),
        )
    }

    fn request_url(request: &ChildGrantRequest) -> Url {
        let mut url = Url::parse("https://accounts.example/authorize?tenant=a").unwrap();
        url.query_pairs_mut()
            .append_pair("cid", request.callback().as_str())
            .append_pair("caps", &request.capabilities().to_string())
            .append_pair("cpk", &request.client_pk().z32())
            .append_pair(
                "epk",
                &URL_SAFE_NO_PAD.encode(request.ephemeral_public_key()),
            )
            .append_pair("state", request.state());
        url
    }

    #[test]
    fn reads_every_field_from_the_url() {
        let request = request();
        assert_eq!(
            ChildGrantRequest::parse(&request_url(&request)).unwrap(),
            request
        );
    }

    #[test]
    fn rejects_inexact_callbacks_and_invalid_state() {
        let replace = |from: &str, to: &str| {
            let url = request_url(&request());
            Url::parse(&url.as_str().replace(from, to)).unwrap()
        };
        for url in [
            replace("https%3A%2F%2Fchat", "http%3A%2F%2Fchat"),
            replace("https%3A%2F%2Fchat", "https%3A%2F%2FCHAT"),
            replace("state=state-1", "state="),
            replace("state=state-1", &format!("state={}", "s".repeat(129))),
        ] {
            assert!(ChildGrantRequest::parse(&url).is_err(), "{url}");
        }
    }

    #[test]
    fn responses_only_use_the_fragment_of_the_exact_callback() {
        let request = request();
        for url in [
            request.approved_url(b"sealed"),
            request.declined_url(RedirectDenial::AccessDenied),
        ] {
            assert_eq!(
                url.as_str().split('#').next(),
                Some(CALLBACK),
                "response data must stay out of the path and query"
            );
            assert!(url.fragment().unwrap().contains("state=state-1"));
        }
    }
}

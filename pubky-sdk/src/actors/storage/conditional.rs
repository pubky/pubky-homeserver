//! Conditional writes and verified reads.
//!
//! A homeserver advertising `conditional-writes` in `/info` enforces
//! `If-Match` and `If-None-Match` on storage `PUT` and `DELETE`, and every
//! `ETag` it reports is the base64 blake3 hash of the content. Together these
//! give compare-and-set over a stored file:
//!
//! 1. Read the file with [`SessionStorage::get_verified`] or
//!    [`PublicStorage::get_verified`], which checks that the body hashes to
//!    the `ETag` it came with.
//! 2. Write it back with [`SessionStorage::put_if_match`] and that `ETag`.
//!    A [`RequestError::PreconditionFailed`] means someone else wrote first:
//!    re-read and try again.
//! 3. Create-once files use [`SessionStorage::put_if_absent`].
//!
//! Every conditional call first checks that the user's homeserver advertises
//! the feature and fails with [`RequestError::UnsupportedFeature`] otherwise,
//! because an older homeserver ignores the headers and writes
//! unconditionally.
//!
//! Entity tags are handled in the form [`ResourceStats::etag`] reports them:
//! the opaque value without quotes. Quoted values are accepted too.
//!
//! Two consequences of the tag being a content hash rather than a version
//! counter:
//!
//! - A file that is changed and then changed back carries its original tag
//!   again, and [`SessionStorage::put_if_match`] with that tag succeeds. The
//!   guarantee is "the content is what I last saw", not "nobody wrote".
//! - A write whose response is lost, because the connection dropped after
//!   the server committed, has still landed. Retrying it blindly can then
//!   fail with [`RequestError::PreconditionFailed`]. Before retrying, read
//!   the file back and compare its tag with [`content_etag`] of the body
//!   you sent: equal means the first attempt won.

use base64::Engine;
use pubky_common::constants::features::CONDITIONAL_WRITES;
use reqwest::{
    Method, Response,
    header::{ETAG, IF_MATCH, IF_NONE_MATCH},
};

use super::core::{PublicStorage, SessionStorage};
use super::resource::{IntoPubkyResource, IntoResourcePath};
use super::stats::{ResourceStats, clean_etag};
use super::verbs::send_checked;
use crate::{Result, cross_log, errors::RequestError};

/// How many times a verified read is attempted before its verification
/// failure is reported. A mismatch is usually a read that raced a
/// concurrent write, and resolves within milliseconds.
const VERIFIED_READ_ATTEMPTS: usize = 3;

/// A body read from storage together with the entity tag it was verified
/// against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBody {
    /// The content.
    pub bytes: Vec<u8>,
    /// Its entity tag, without quotes, equal to [`content_etag`] of `bytes`.
    pub etag: String,
}

/// The entity tag a homeserver reports for `bytes`: its blake3 hash, base64
/// encoded, without quotes.
///
/// Use it to verify a body against a reported `ETag`, or to write with
/// [`SessionStorage::put_if_match`] against content you have in hand.
#[must_use]
pub fn content_etag(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(pubky_common::crypto::hash(bytes).as_bytes())
}

/// The quoted, strong form of an entity tag for an `If-Match` header.
///
/// Accepts the opaque value with or without quotes. Weak tags are rejected:
/// `If-Match` uses strong comparison, so they could never match.
fn strong_entity_tag(etag: &str) -> Result<String> {
    let etag = etag.trim();
    if etag.starts_with("W/") {
        return Err(RequestError::Validation {
            message: "weak entity tags cannot be used with If-Match".to_string(),
        }
        .into());
    }
    let opaque = etag
        .strip_prefix('"')
        .and_then(|rest| rest.strip_suffix('"'))
        .unwrap_or(etag);
    let is_etagc = |byte: u8| byte == b'!' || (b'#'..=b'~').contains(&byte);
    if opaque.is_empty() || !opaque.bytes().all(is_etagc) {
        return Err(RequestError::Validation {
            message: format!("invalid entity tag: {etag:?}"),
        }
        .into());
    }
    Ok(format!("\"{opaque}\""))
}

/// The entity tag a write response reports for what it stored.
fn stored_etag(response: &Response) -> Result<String> {
    response
        .headers()
        .get(ETAG)
        .and_then(|value| value.to_str().ok())
        .map(clean_etag)
        .ok_or_else(|| {
            RequestError::Verification {
                message: "the response carries no ETag".to_string(),
            }
            .into()
        })
}

/// Read the body and check it hashes to the `ETag` it came with.
async fn verify_body(response: Response) -> Result<VerifiedBody> {
    let etag = stored_etag(&response)?;
    let bytes = response.bytes().await?.to_vec();
    let actual = content_etag(&bytes);
    if actual != etag {
        return Err(RequestError::Verification {
            message: format!("the body hashes to {actual} but the ETag is {etag}"),
        }
        .into());
    }
    Ok(VerifiedBody { bytes, etag })
}

/// Fetch and verify, retrying a verification failure a few times since it is
/// usually a read that raced a concurrent write.
async fn get_verified_with<F, Fut>(fetch: F) -> Result<VerifiedBody>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<Response>>,
{
    let mut attempt = 1;
    loop {
        match verify_body(fetch().await?).await {
            Err(crate::Error::Request(RequestError::Verification { message }))
                if attempt < VERIFIED_READ_ATTEMPTS =>
            {
                cross_log!(
                    debug,
                    "Verified read attempt {attempt} failed ({message}); retrying"
                );
                attempt += 1;
            }
            result => return result,
        }
    }
}

impl SessionStorage {
    /// Fail unless the user's homeserver enforces conditional writes.
    async fn ensure_conditional_writes(&self) -> Result<()> {
        if self
            .client
            .homeserver_supports(&self.user, CONDITIONAL_WRITES)
            .await
        {
            return Ok(());
        }
        Err(RequestError::UnsupportedFeature {
            feature: CONDITIONAL_WRITES.to_string(),
        }
        .into())
    }

    /// Write `body` to `path` only if the stored content still has entity
    /// tag `etag`. Returns the entity tag of what was written.
    ///
    /// # Errors
    /// - [`RequestError::PreconditionFailed`] if the stored content has
    ///   changed, or nothing is stored there. Re-read and retry.
    /// - [`RequestError::UnsupportedFeature`] if the homeserver does not
    ///   advertise `conditional-writes`.
    /// - [`RequestError::Validation`] if `etag` is not a strong entity tag.
    pub async fn put_if_match<P, B>(&self, path: P, body: B, etag: &str) -> Result<String>
    where
        P: IntoResourcePath,
        B: Into<reqwest::Body>,
    {
        let if_match = strong_entity_tag(etag)?;
        self.ensure_conditional_writes().await?;
        let rb = self
            .request(Method::PUT, path)
            .await?
            .header(IF_MATCH, if_match)
            .body(body);
        stored_etag(&send_checked(rb).await?)
    }

    /// Write `body` to `path` only if nothing is stored there yet. Returns
    /// the entity tag of what was written.
    ///
    /// # Errors
    /// - [`RequestError::PreconditionFailed`] if the path already exists.
    /// - [`RequestError::UnsupportedFeature`] if the homeserver does not
    ///   advertise `conditional-writes`.
    pub async fn put_if_absent<P, B>(&self, path: P, body: B) -> Result<String>
    where
        P: IntoResourcePath,
        B: Into<reqwest::Body>,
    {
        self.ensure_conditional_writes().await?;
        let rb = self
            .request(Method::PUT, path)
            .await?
            .header(IF_NONE_MATCH, "*")
            .body(body);
        stored_etag(&send_checked(rb).await?)
    }

    /// Delete `path` only if the stored content still has entity tag `etag`.
    ///
    /// # Errors
    /// - [`RequestError::PreconditionFailed`] if the stored content has
    ///   changed.
    /// - [`RequestError::Server`] with `404` if nothing is stored there.
    /// - [`RequestError::UnsupportedFeature`] if the homeserver does not
    ///   advertise `conditional-writes`.
    /// - [`RequestError::Validation`] if `etag` is not a strong entity tag.
    pub async fn delete_if_match<P: IntoResourcePath>(&self, path: P, etag: &str) -> Result<()> {
        let if_match = strong_entity_tag(etag)?;
        self.ensure_conditional_writes().await?;
        let rb = self
            .request(Method::DELETE, path)
            .await?
            .header(IF_MATCH, if_match);
        send_checked(rb).await.map(|_| ())
    }

    /// Read `path` and verify that the body hashes to the `ETag` it came
    /// with, retrying a mismatch a few times.
    ///
    /// # Errors
    /// - [`RequestError::Verification`] if the body still does not match
    ///   its `ETag` after the retries.
    pub async fn get_verified<P: IntoResourcePath + Clone>(&self, path: P) -> Result<VerifiedBody> {
        get_verified_with(|| self.get(path.clone())).await
    }
}

impl PublicStorage {
    /// Read an addressed resource and verify that the body hashes to the
    /// `ETag` it came with, retrying a mismatch a few times.
    ///
    /// # Errors
    /// - [`RequestError::Verification`] if the body still does not match
    ///   its `ETag` after the retries.
    pub async fn get_verified<A: IntoPubkyResource + Clone>(
        &self,
        addr: A,
    ) -> Result<VerifiedBody> {
        get_verified_with(|| self.get(addr.clone())).await
    }
}

impl ResourceStats {
    /// The entity tag in the form [`SessionStorage::put_if_match`] takes,
    /// if the server reported one.
    #[must_use]
    pub fn strong_etag(&self) -> Option<&str> {
        self.etag.as_deref().filter(|etag| !etag.starts_with("W/"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        deprecated,
        reason = "the cookie credential is the simplest one to build without a server"
    )]

    use std::{num::NonZeroUsize, sync::Arc};

    use pkarr::{Cache, InMemoryCache, SignedPacket, dns::rdata::SVCB};
    use pubky_common::{
        capabilities::{Capabilities, Capability},
        session::CookieSessionRecord,
    };

    use super::*;
    use crate::{Keypair, PubkyHttpClient, PublicKey, actors::auth::cookie::CookieCredential};

    /// A session for `user` on a client that resolves the user's homeserver
    /// from a seeded pkarr cache and already knows the homeserver's features,
    /// so no network is involved.
    fn offline_session(
        user: &Keypair,
        homeserver: &PublicKey,
        features: &[&str],
    ) -> SessionStorage {
        let host = homeserver.z32();
        let svcb = SVCB::new(0, host.as_str().try_into().unwrap());
        let packet = SignedPacket::builder()
            .https("_pubky".try_into().unwrap(), svcb, 3600)
            .sign(user)
            .unwrap();
        let cache = Arc::new(InMemoryCache::new(NonZeroUsize::MIN));
        cache.put(&user.public_key().as_inner().into(), &packet);

        let mut builder = PubkyHttpClient::builder();
        builder
            .isolated_pkarr_test()
            .pkarr(|pkarr| pkarr.cache(cache));
        let client = builder.build().unwrap();
        client.features.insert(homeserver, features);

        let user = user.public_key();
        let record =
            CookieSessionRecord::new(&user, Capabilities::from(vec![Capability::root()]), None);
        let credential = CookieCredential::new(
            user.clone(),
            Some("test-cookie".to_string()),
            record,
            Some(homeserver.clone()),
        );
        SessionStorage {
            client,
            user,
            credential: Arc::new(credential),
        }
    }

    fn assert_unsupported(result: &Result<impl std::fmt::Debug>) {
        assert!(
            matches!(
                result,
                Err(crate::Error::Request(RequestError::UnsupportedFeature { feature }))
                    if feature == CONDITIONAL_WRITES
            ),
            "expected UnsupportedFeature, got {result:?}"
        );
    }

    /// The gate that keeps a conditional write from reaching a homeserver
    /// that would ignore its headers and overwrite unconditionally.
    #[tokio::test]
    async fn conditional_writes_refuse_a_homeserver_without_the_feature() {
        let user = Keypair::random();
        let homeserver = Keypair::random().public_key();
        let storage = offline_session(&user, &homeserver, &["path-addressed-storage"]);
        let etag = content_etag(b"v1");

        assert_unsupported(&storage.put_if_match("/pub/app/x", "v2", &etag).await);
        assert_unsupported(&storage.put_if_absent("/pub/app/x", "v1").await);
        assert_unsupported(&storage.delete_if_match("/pub/app/x", &etag).await);
    }

    #[tokio::test]
    async fn conditional_writes_refuse_an_unresolvable_homeserver() {
        let mut builder = PubkyHttpClient::builder();
        builder.isolated_pkarr_test();
        let user = Keypair::random();
        let storage = SessionStorage {
            client: builder.build().unwrap(),
            user: user.public_key(),
            credential: offline_session(&user, &Keypair::random().public_key(), &[]).credential,
        };

        assert_unsupported(&storage.put_if_absent("/pub/app/x", "v1").await);
    }

    #[test]
    fn content_etag_is_the_base64_blake3_hash() {
        let expected =
            base64::engine::general_purpose::STANDARD.encode(blake3_hash_of(b"hello").as_slice());
        assert_eq!(content_etag(b"hello"), expected);
        assert_ne!(content_etag(b"hello"), content_etag(b"hellp"));
    }

    fn blake3_hash_of(bytes: &[u8]) -> Vec<u8> {
        pubky_common::crypto::hash(bytes).as_bytes().to_vec()
    }

    #[test]
    fn strong_entity_tag_accepts_quoted_and_bare_values() {
        assert_eq!(strong_entity_tag("abc").unwrap(), "\"abc\"");
        assert_eq!(strong_entity_tag("\"abc\"").unwrap(), "\"abc\"");
        assert_eq!(strong_entity_tag("  abc/+= ").unwrap(), "\"abc/+=\"");
    }

    #[test]
    fn strong_entity_tag_rejects_weak_and_malformed_values() {
        for bad in ["W/\"abc\"", "W/abc", "", "\"\"", "has space", "a\"b"] {
            assert!(
                matches!(
                    strong_entity_tag(bad),
                    Err(crate::Error::Request(RequestError::Validation { .. }))
                ),
                "{bad:?} should be rejected"
            );
        }
    }
}

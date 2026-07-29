use std::{fmt, pin::Pin, sync::Arc};

use pubky_common::{
    auth::jws::{finish_jws, jws_signing_input},
    crypto::{Keypair, PublicKey},
};
use serde::Serialize;

use crate::errors::Result;

/// Boxed future returned by a delegated grant PoP signing callback.
///
/// The future resolves to raw Ed25519 signature bytes for a precomputed JWS
/// signing input. Native builds require `Send` because the SDK may move futures
/// across threads.
#[doc(hidden)]
#[cfg(not(target_arch = "wasm32"))]
pub type BoxSignFuture = Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'static>>;
/// Boxed future returned by a delegated grant PoP signing callback.
///
/// The future resolves to raw Ed25519 signature bytes for a precomputed JWS
/// signing input. WASM builds intentionally do not require `Send` because
/// browser futures such as `JsFuture` are single-threaded.
#[doc(hidden)]
#[cfg(target_arch = "wasm32")]
pub type BoxSignFuture = Pin<Box<dyn Future<Output = Result<Vec<u8>>> + 'static>>;
/// Async signing callback used by delegated grant PoP signers.
///
/// The input is the exact JWS signing input (`base64url(header) + "." +
/// base64url(claims)`). The callback must sign those bytes with the delegated
/// Ed25519 private key and return the raw signature bytes. This is hidden
/// because it exists to let the JS/WASM binding inject WebCrypto signing.
#[doc(hidden)]
pub type DelegatedSignFn = Arc<dyn Fn(String) -> BoxSignFuture + Send + Sync + 'static>;

/// Internal signer used for grant Proof-of-Possession JWS values.
/// Can be either a local keypair or a delegated signer with signing logic implemented outside the SDK, for example in a browser `WebCrypto`.
#[derive(Clone)]
pub(crate) enum GrantPopSigner {
    /// Keypair owned by the SDK
    Local(Keypair),
    /// Delegated signer with signing logic implemented outside the SDK, for example in a browser `WebCrypto`.
    Delegated(DelegatedGrantPopSigner),
}

impl fmt::Debug for GrantPopSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Local(keypair) => f.debug_tuple("Local").field(&keypair.public_key()).finish(),
            Self::Delegated(signer) => f.debug_tuple("Delegated").field(signer).finish(),
        }
    }
}

impl GrantPopSigner {
    pub(crate) fn local(keypair: Keypair) -> Self {
        Self::Local(keypair)
    }

    pub(crate) fn delegated(key_id: String, public_key: PublicKey, sign: DelegatedSignFn) -> Self {
        Self::Delegated(DelegatedGrantPopSigner {
            key_id,
            public_key,
            sign,
        })
    }

    /// Public key for the signer, used in the grant `cnf` claim and JWS header `jwk` field.
    pub(crate) fn public_key(&self) -> PublicKey {
        match self {
            Self::Local(keypair) => keypair.public_key(),
            Self::Delegated(signer) => signer.public_key.clone(),
        }
    }

    /// Signs the given claims as a JWS with the appropriate signing input format for `PoP` proofs, and returns the complete JWS string.
    pub(crate) async fn sign_jws<T: Serialize>(&self, typ: &str, claims: &T) -> Result<String> {
        let signing_input = jws_signing_input(typ, claims);
        match self {
            Self::Local(keypair) => {
                let signature = keypair.sign(signing_input.as_bytes());
                Ok(finish_jws(signing_input, signature.to_bytes()))
            }
            Self::Delegated(signer) => signer.sign_jws(signing_input).await,
        }
    }

    /// Returns the local secret key if this is a local signer, or `None` if it's a delegated signer which does not expose the secret key material.
    pub(crate) fn local_secret(&self) -> Option<[u8; 32]> {
        match self {
            Self::Local(keypair) => Some(keypair.secret()),
            Self::Delegated(_) => None,
        }
    }

    /// Returns the delegated signer state if this is a delegated signer, or `None` if it's a local signer.
    pub(crate) fn delegated_state(&self) -> Option<DelegatedGrantPopSigner> {
        match self {
            Self::Local(_) => None,
            Self::Delegated(signer) => Some(signer.clone()),
        }
    }
}

/// Externally held signer state for delegated grant `PoP` signing, containing the public key and an async signing callback, but not the secret key material.
#[derive(Clone)]
pub struct DelegatedGrantPopSigner {
    /// `IndexedDB` key id for the non-extractable private `CryptoKey`.
    pub key_id: String,
    /// Public key bound by the grant `cnf` claim.
    pub public_key: PublicKey,
    sign: DelegatedSignFn,
}

impl fmt::Debug for DelegatedGrantPopSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DelegatedGrantPopSigner")
            .field("key_id", &self.key_id)
            .field("public_key", &self.public_key)
            .finish_non_exhaustive()
    }
}

impl DelegatedGrantPopSigner {
    /// Signs the given JWS signing input using the provided async signing callback, and returns the complete JWS string.
    async fn sign_jws(&self, signing_input: String) -> Result<String> {
        let signature = (self.sign)(signing_input.clone()).await?;
        Ok(finish_jws(signing_input, signature))
    }
}

/// Box user-provided async signing logic into the delegated signer callback type.
///
/// This exists for the JS/WASM binding, which supplies a callback that signs the
/// JWS signing input with a browser-held WebCrypto key.
#[doc(hidden)]
#[cfg(not(target_arch = "wasm32"))]
pub fn delegated_sign_callback<F, Fut>(sign: F) -> DelegatedSignFn
where
    F: Fn(String) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Vec<u8>>> + Send + 'static,
{
    Arc::new(move |signing_input| Box::pin(sign(signing_input)))
}

/// Box user-provided async signing logic into the delegated signer callback type.
///
/// This exists for the JS/WASM binding, which supplies a callback that signs the
/// JWS signing input with a browser-held WebCrypto key.
#[doc(hidden)]
#[cfg(target_arch = "wasm32")]
pub fn delegated_sign_callback<F, Fut>(sign: F) -> DelegatedSignFn
where
    F: Fn(String) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Vec<u8>>> + 'static,
{
    Arc::new(move |signing_input| Box::pin(sign(signing_input)))
}

#[cfg(test)]
mod tests {
    use pubky_common::auth::{
        jws::{POP_JWS_TYP, sign_jws},
        pop::PopProofClaims,
    };

    use super::*;
    use crate::actors::auth::grant::credential::now_unix;

    #[tokio::test]
    async fn local_signer_matches_common_jws_signing() {
        let keypair = Keypair::random();
        let claims = PopProofClaims {
            aud: Keypair::random().public_key(),
            gid: pubky_common::auth::jws::GrantId::generate(),
            nonce: pubky_common::auth::jws::PopNonce::generate(),
            iat: now_unix(),
        };
        let signer = GrantPopSigner::local(keypair.clone());

        let actual = signer.sign_jws(POP_JWS_TYP, &claims).await.unwrap();
        let expected = sign_jws(&keypair, POP_JWS_TYP, &claims);

        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn delegated_signer_sign_value() {
        #[derive(serde::Serialize)]
        struct DummyClaims;
        let claims = DummyClaims {};

        let signer = GrantPopSigner::delegated(
            "delegated-test-key".into(),
            Keypair::random().public_key(),
            delegated_sign_callback(|_| async { Ok(vec![0; 64]) }),
        );

        let signed_jwt = signer.sign_jws("test", &claims).await.unwrap();
        let base64_signature = signed_jwt.split('.').nth(2).unwrap();
        assert_eq!(
            base64_signature,
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "Signature is all zeros which is all 'A' in base64"
        );
    }
}

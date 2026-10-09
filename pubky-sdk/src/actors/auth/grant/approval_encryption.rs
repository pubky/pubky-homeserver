//! HPKE transport for grant approvals.

use hpke::{
    Deserializable, Kem, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::X25519HkdfSha256, single_shot_open, single_shot_seal,
};
use pubky_common::crypto::random_bytes;
use zeroize::Zeroizing;

use crate::errors::{AuthError, Result};

type ApprovalKem = X25519HkdfSha256;

const INFO: &[u8] = b"pubky-grant-approval-hpke-v1";
const WIRE_PREFIX: &[u8] = b"pubky-hpke-v1\0";

/// Temporary recipient key for one pending grant approval.
#[derive(Clone)]
pub(crate) struct ApprovalRecipientSecret(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for ApprovalRecipientSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl ApprovalRecipientSecret {
    pub(crate) fn generate() -> (Self, [u8; 32]) {
        let ikm = Zeroizing::new(random_bytes::<32>());
        let (private_key, public_key) = ApprovalKem::derive_keypair(&*ikm);
        let mut secret = Zeroizing::new([0; 32]);
        private_key.write_exact(&mut secret[..]);
        let public: [u8; 32] = public_key.to_bytes().into();
        (Self(secret), public)
    }

    pub(crate) fn from_bytes(secret: [u8; 32]) -> Self {
        Self(Zeroizing::new(secret))
    }

    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        *self.0
    }

    pub(crate) fn public_key(&self) -> [u8; 32] {
        let private_key = <ApprovalKem as Kem>::PrivateKey::from_bytes(&*self.0)
            .expect("stored approval secret is a valid X25519 private key");
        <ApprovalKem as Kem>::sk_to_pk(&private_key)
            .to_bytes()
            .into()
    }

    pub(crate) fn matches_public_key(&self, expected: &[u8; 32]) -> bool {
        self.public_key() == *expected
    }

    pub(crate) fn open(&self, wire: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let invalid = || AuthError::Validation("invalid HPKE grant approval".into());
        if !wire.starts_with(WIRE_PREFIX) {
            return Err(invalid().into());
        }

        let body = &wire[WIRE_PREFIX.len()..];
        let encapped_len = <ApprovalKem as Kem>::EncappedKey::size();
        if body.len() <= encapped_len {
            return Err(invalid().into());
        }

        let private_key =
            <ApprovalKem as Kem>::PrivateKey::from_bytes(&*self.0).map_err(|_error| invalid())?;
        let encapped_key = <ApprovalKem as Kem>::EncappedKey::from_bytes(&body[..encapped_len])
            .map_err(|_error| invalid())?;
        let plaintext = single_shot_open::<ChaCha20Poly1305, HkdfSha256, ApprovalKem>(
            &OpModeR::Base,
            &private_key,
            &encapped_key,
            INFO,
            &body[encapped_len..],
            b"",
        )
        .map_err(|_error| invalid())?;
        Ok(Zeroizing::new(plaintext))
    }
}

pub(crate) fn seal(public_key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let public_key = <ApprovalKem as Kem>::PublicKey::from_bytes(public_key)
        .map_err(|_error| AuthError::Validation("invalid HPKE approval public key".into()))?;
    let (encapped_key, ciphertext) = single_shot_seal::<ChaCha20Poly1305, HkdfSha256, ApprovalKem>(
        &OpModeS::Base,
        &public_key,
        INFO,
        plaintext,
        b"",
    )
    .map_err(|_error| AuthError::Validation("failed to encrypt HPKE grant approval".into()))?;

    let encapped_key = encapped_key.to_bytes();
    let mut wire = Vec::with_capacity(WIRE_PREFIX.len() + encapped_key.len() + ciphertext.len());
    wire.extend_from_slice(WIRE_PREFIX);
    wire.extend_from_slice(&encapped_key);
    wire.extend_from_slice(&ciphertext);
    Ok(wire)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_round_trips_and_rejects_wrong_keys_and_unmarked_payloads() {
        let (recipient, public_key) = ApprovalRecipientSecret::generate();
        let plaintext = b"signed approval";
        let ciphertext = seal(&public_key, plaintext).unwrap();

        assert_eq!(&*recipient.open(&ciphertext).unwrap(), plaintext);
        assert!(
            ApprovalRecipientSecret::generate()
                .0
                .open(&ciphertext)
                .is_err()
        );
        assert!(recipient.open(plaintext).is_err());
    }

    #[test]
    fn relay_cannot_encrypt_approval_with_its_channel_id() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        let (recipient, public_key) = ApprovalRecipientSecret::generate();
        let channel = crate::actors::auth::deep_links::GrantRelayChannel::Hpke {
            ephemeral_public_key: public_key,
        };
        let channel_id = channel.http_channel_id();
        let mut relay_visible_key = [0; 32];
        URL_SAFE_NO_PAD
            .decode_slice(channel_id, &mut relay_visible_key)
            .unwrap();
        let forged_message = seal(&relay_visible_key, b"forged approval").unwrap();

        assert!(recipient.open(&forged_message).is_err());
    }
}

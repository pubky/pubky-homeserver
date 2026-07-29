//! Client-server Authentication using signed timesteps

use serde::{Deserialize, Serialize};

use crate::{
    capabilities::Capabilities,
    crypto::{Keypair, PublicKey, Signature},
    namespaces::PUBKY_AUTH,
    timestamp::Timestamp,
};

const CURRENT_VERSION: u8 = 0;
// 3 minutes in the past or the future
const TIMESTAMP_WINDOW: i64 = 180 * 1_000_000;

mod signature_serde {
    use core::fmt;

    use serde::{
        de::{self, SeqAccess, Visitor},
        ser::SerializeTuple,
        Deserializer, Serializer,
    };

    use crate::crypto::Signature;

    pub fn serialize<S: Serializer>(
        signature: &Signature,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut tuple = serializer.serialize_tuple(Signature::BYTE_SIZE)?;

        for byte in signature.to_bytes() {
            tuple.serialize_element(&byte)?;
        }

        tuple.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Signature, D::Error> {
        struct SignatureVisitor;

        impl<'de> Visitor<'de> for SignatureVisitor {
            type Value = Signature;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a 64-byte Ed25519 signature")
            }

            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut bytes = [0; Signature::BYTE_SIZE];

                for (index, byte) in bytes.iter_mut().enumerate() {
                    *byte = sequence
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(index, &self))?;
                }

                Ok(Signature::from_bytes(&bytes))
            }
        }

        deserializer.deserialize_tuple(Signature::BYTE_SIZE, SignatureVisitor)
    }
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
/// Authentication token used by the Pubky Auth protocol.
pub struct AuthToken {
    /// Signature over the token.
    #[serde(with = "signature_serde")]
    signature: Signature,
    /// A namespace to ensure this signature can't be used for any
    /// other purposes that share the same message structurea by accident.
    namespace: [u8; 10],
    /// Version of the [AuthToken], in case we need to upgrade it to support unforeseen usecases.
    ///
    /// Version 0:
    /// - Signer is implicitly the same as the root keypair for
    ///   the [AuthToken::public_key], without any delegation.
    /// - Capabilities are only meant for resoucres on the homeserver.
    version: u8,
    /// Timestamp
    timestamp: Timestamp,
    /// The [PublicKey] of the owner of the resources being accessed by this token.
    public_key: PublicKey,
    // Variable length capabilities
    capabilities: Capabilities,
}

impl AuthToken {
    /// Sign a new AuthToken with given capabilities.
    pub fn sign(keypair: &Keypair, capabilities: impl Into<Capabilities>) -> Self {
        let timestamp = Timestamp::now();

        let mut token = Self {
            signature: Signature::from_bytes(&[0; 64]),
            namespace: *PUBKY_AUTH,
            version: 0,
            timestamp,
            public_key: keypair.public_key(),
            capabilities: capabilities.into(),
        };

        let serialized = token.serialize();

        token.signature = keypair.sign(&serialized[65..]);

        token
    }

    // === Getters ===

    /// Returns the public key that is providing this AuthToken
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Returns the capabilities in this AuthToken.
    pub fn capabilities(&self) -> &Capabilities {
        &self.capabilities
    }

    /// Returns the timestamp of this AuthToken.
    pub fn timestamp(&self) -> Timestamp {
        self.timestamp
    }

    // === Public Methods ===

    /// Parse and verify an AuthToken.
    pub fn verify(bytes: &[u8]) -> Result<Self, Error> {
        if bytes[74] > CURRENT_VERSION {
            return Err(Error::UnknownVersion);
        }

        let token = AuthToken::deserialize(bytes)?;

        match token.version {
            0 => {
                let now = Timestamp::now();

                // Chcek timestamp;
                let diff = token.timestamp.as_u64() as i64 - now.as_u64() as i64;
                if diff > TIMESTAMP_WINDOW {
                    return Err(Error::TooFarInTheFuture);
                }
                if diff < -TIMESTAMP_WINDOW {
                    return Err(Error::Expired);
                }

                token
                    .public_key
                    .verify(AuthToken::signable(token.version, bytes), &token.signature)
                    .map_err(|_| Error::InvalidSignature)?;

                Ok(token)
            }
            _ => unreachable!(),
        }
    }

    /// Serialize this AuthToken to its canonical binary representation.
    pub fn serialize(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap()
    }

    /// Deserialize an AuthToken from its canonical binary representation.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        Ok(postcard::from_bytes(bytes)?)
    }

    fn signable(version: u8, bytes: &[u8]) -> &[u8] {
        match version {
            0 => bytes[65..].into(),
            _ => unreachable!(),
        }
    }
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
/// Error verifying an [AuthToken]
pub enum Error {
    #[error("Unknown version")]
    /// Unknown version
    UnknownVersion,
    #[error("AuthToken has a timestamp that is more than 3 minutes in the future")]
    /// AuthToken has a timestamp that is more than 3 minutes in the future
    TooFarInTheFuture,
    #[error("AuthToken has a timestamp that is more than 3 minutes in the past")]
    /// AuthToken has a timestamp that is more than 3 minutes in the past
    Expired,
    #[error("Invalid Signature")]
    /// Invalid Signature
    InvalidSignature,
    #[error(transparent)]
    /// Error parsing [AuthToken] using Postcard
    Parsing(#[from] postcard::Error),
    #[error("AuthToken already used")]
    /// AuthToken already used
    AlreadyUsed,
}

#[cfg(test)]
mod tests {
    use crate::{
        auth::auth_token::TIMESTAMP_WINDOW, capabilities::Capability, crypto::Keypair,
        timestamp::Timestamp,
    };

    use super::*;

    #[test]
    fn sign_verify() {
        let signer = Keypair::random();
        let capabilities = vec![Capability::root()];

        let token = AuthToken::sign(&signer, capabilities.clone());

        let serialized = &token.serialize();
        assert_eq!(serialized[..64], token.signature.to_bytes());
        assert_eq!(&serialized[64..74], PUBKY_AUTH);
        assert_eq!(serialized[74], CURRENT_VERSION);

        let verified = AuthToken::verify(serialized).unwrap();

        assert_eq!(verified.capabilities, capabilities.into());
    }

    #[test]
    fn expired() {
        let signer = Keypair::random();
        let timestamp = (Timestamp::now()) - (TIMESTAMP_WINDOW as u64);
        let token = sign_with_timestamp(&signer, timestamp);

        let result = AuthToken::verify(&token.serialize());

        assert_eq!(result, Err(Error::Expired));
    }

    /// Build a validly signed AuthToken with an arbitrary timestamp.
    fn sign_with_timestamp(signer: &Keypair, timestamp: Timestamp) -> AuthToken {
        let mut token = AuthToken {
            signature: Signature::from_bytes(&[0; 64]),
            namespace: *PUBKY_AUTH,
            version: 0,
            timestamp,
            public_key: signer.public_key(),
            capabilities: Capabilities::from(vec![Capability::root()]),
        };

        let serialized = token.serialize();
        token.signature = signer.sign(&serialized[65..]);

        token
    }

    #[test]
    fn too_far_in_future() {
        let signer = Keypair::random();

        let timestamp = Timestamp::now() + (TIMESTAMP_WINDOW as u64 + 5_000_000);
        let token = sign_with_timestamp(&signer, timestamp);

        assert_eq!(
            AuthToken::verify(&token.serialize()),
            Err(Error::TooFarInTheFuture)
        );
    }

    #[test]
    fn within_window() {
        let signer = Keypair::random();

        // Just inside the past boundary (TIMESTAMP_WINDOW minus 5 seconds)
        let past_token = sign_with_timestamp(
            &signer,
            Timestamp::now() - (TIMESTAMP_WINDOW as u64 - 5_000_000),
        );
        AuthToken::verify(&past_token.serialize()).unwrap();

        // Just inside the future boundary (TIMESTAMP_WINDOW minus 5 seconds)
        let future_token = sign_with_timestamp(
            &signer,
            Timestamp::now() + (TIMESTAMP_WINDOW as u64 - 5_000_000),
        );
        AuthToken::verify(&future_token.serialize()).unwrap();
    }

    #[test]
    fn unknown_version() {
        let signer = Keypair::random();
        let token = AuthToken {
            signature: Signature::from_bytes(&[0; 64]),
            namespace: *PUBKY_AUTH,
            version: 1,
            timestamp: Timestamp::now(),
            public_key: signer.public_key(),
            capabilities: Capabilities::from(vec![Capability::root()]),
        };
        let serialized = token.serialize();

        assert_eq!(AuthToken::verify(&serialized), Err(Error::UnknownVersion));
    }
}

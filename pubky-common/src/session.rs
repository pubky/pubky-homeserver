//! Pubky homeserver session types.

use postcard::{from_bytes, to_extend};
use serde::{Deserialize, Serialize};

extern crate alloc;
use alloc::vec::Vec;

use crate::{
    capabilities::{Capabilities, Capability},
    crypto::PublicKey,
    timestamp::Timestamp,
};

/// Cookie-specific session record with binary (postcard) serialization.
///
/// This is the legacy wire format used by the cookie auth flow. It carries
/// deprecated fields (`name`, `user_agent`) and a `version` byte for backward
/// compatibility with existing clients.
///
/// When the cookie flow is retired, this struct can be deleted.
#[derive(Clone, Serialize, Deserialize, Debug, Eq, PartialEq)]
pub struct CookieSessionRecord {
    version: usize,
    public_key: PublicKey,
    created_at: u64,
    /// Deprecated. Will always be empty.
    name: String,
    /// Deprecated. Will always be empty.
    user_agent: String,
    capabilities: Vec<Capability>,
}

impl CookieSessionRecord {
    /// Create a new cookie session record.
    pub fn new(
        public_key: &PublicKey,
        capabilities: Capabilities,
        user_agent: Option<String>,
    ) -> Self {
        Self {
            version: 0,
            public_key: public_key.clone(),
            created_at: Timestamp::now().as_u64(),
            capabilities: capabilities.into(),
            user_agent: user_agent.as_deref().unwrap_or("").to_string(),
            name: user_agent.as_deref().unwrap_or("").to_string(),
        }
    }

    // === Getters ===

    /// Returns the public_key of this session authorizes for.
    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    /// Returns the capabilities this session provide on this session's public_key's resources.
    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }

    /// Returns the timestamp when this session was created.
    pub fn created_at(&self) -> u64 {
        self.created_at
    }

    // === Setters ===

    /// Set the timestamp when this session was created.
    pub fn set_created_at(&mut self, created_at: u64) -> &mut Self {
        self.created_at = created_at;
        self
    }

    /// Set this session's capabilities.
    pub fn set_capabilities(&mut self, capabilities: Capabilities) -> &mut Self {
        self.capabilities = capabilities.into();

        self
    }

    // === Public Methods ===

    /// Serialize this session to its canonical binary representation.
    pub fn serialize(&self) -> Vec<u8> {
        to_extend(self, Vec::new()).expect("CookieSessionRecord::serialize")
    }

    /// Deserialize this session from its canonical binary representation.
    pub fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Error::EmptyPayload);
        }

        if bytes[0] > 0 {
            return Err(Error::UnknownVersion);
        }

        Ok(from_bytes(bytes)?)
    }

    // TODO: add `can_read()`, `can_write()` and `is_root()` methods
}

#[derive(thiserror::Error, Debug, PartialEq)]
/// Error deserializing a [CookieSessionRecord].
pub enum Error {
    #[error("Empty payload")]
    /// Empty payload
    EmptyPayload,
    #[error("Unknown version")]
    /// Unknown version
    UnknownVersion,
    #[error(transparent)]
    /// Error parsing the binary representation.
    Parsing(#[from] postcard::Error),
}

#[cfg(test)]
mod tests {
    use crate::{capabilities::Capability, crypto::Keypair};

    use super::*;

    #[test]
    fn serialize() {
        let keypair = Keypair::from_secret(&[0; 32]);
        let public_key = keypair.public_key();
        let capabilities = Capabilities::builder().cap(Capability::root()).finish();

        let session = CookieSessionRecord {
            user_agent: "foo".to_string(),
            capabilities: capabilities.into(),
            created_at: 0,
            public_key,
            version: 0,
            name: "".to_string(),
        };

        let serialized = session.serialize();

        assert_eq!(
            serialized,
            [
                0, 59, 106, 39, 188, 206, 182, 164, 45, 98, 163, 168, 208, 42, 111, 13, 115, 101,
                50, 21, 119, 29, 226, 67, 166, 58, 192, 72, 161, 139, 89, 218, 41, 0, 0, 3, 102,
                111, 111, 1, 4, 47, 58, 114, 119
            ]
        );

        let deserialized = CookieSessionRecord::deserialize(&serialized).unwrap();

        assert_eq!(deserialized, session)
    }

    #[test]
    fn deserialize() {
        let result = CookieSessionRecord::deserialize(&[]);

        assert_eq!(result, Err(Error::EmptyPayload));
    }
}

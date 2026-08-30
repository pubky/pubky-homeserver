use core::fmt;
use core::ops::{Deref, DerefMut};
use core::str::FromStr;
#[cfg(not(target_arch = "wasm32"))]
use std::{io, path::Path};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

type ParseError = <pkarr::PublicKey as TryFrom<String>>::Error;

/// Wrapper around [`pkarr::Keypair`].
#[derive(Clone)]
pub struct Keypair(pkarr::Keypair);

impl Keypair {
    /// Generate a random keypair.
    #[must_use]
    pub fn random() -> Self {
        Self(pkarr::Keypair::random())
    }

    /// Export the secret bytes used to derive this keypair.
    #[must_use]
    pub fn secret(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(self.0.secret_key().as_ref());
        out
    }

    /// Construct a [`Keypair`] from a 32-byte secret.
    #[must_use]
    pub fn from_secret(secret: &[u8; 32]) -> Self {
        Self(pkarr::Keypair::from_secret_key(secret))
    }

    /// Read a keypair from a pkarr secret key file.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn from_secret_key_file(path: &Path) -> Result<Self, io::Error> {
        pkarr::Keypair::from_secret_key_file(path).map(Self)
    }

    /// Return the [`PublicKey`] associated with this [`Keypair`].
    ///
    /// Display the returned key with `.to_string()` or [`PublicKey::z32()`] to get its z-base32
    /// encoding.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        PublicKey(self.0.public_key())
    }

    /// Borrow the inner [`pkarr::Keypair`].
    #[must_use]
    pub const fn as_inner(&self) -> &pkarr::Keypair {
        &self.0
    }

    /// Persist the secret key to disk using the pkarr format.
    #[cfg(not(target_arch = "wasm32"))]
    pub fn write_secret_key_file(&self, path: &Path) -> Result<(), io::Error> {
        self.0.write_secret_key_file(path)
    }

    /// Extract the inner [`pkarr::Keypair`].
    #[must_use]
    pub fn into_inner(self) -> pkarr::Keypair {
        self.0
    }
}

impl fmt::Debug for Keypair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Deref for Keypair {
    type Target = pkarr::Keypair;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Keypair {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl From<pkarr::Keypair> for Keypair {
    fn from(keypair: pkarr::Keypair) -> Self {
        Self(keypair)
    }
}

impl From<Keypair> for pkarr::Keypair {
    fn from(value: Keypair) -> Self {
        value.0
    }
}

/// Wrapper around [`pkarr::PublicKey`].
///
/// The canonical string representation is raw z-base32. Legacy `pubky<z32>` input remains
/// accepted for compatibility.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PublicKey(pkarr::PublicKey);

impl PublicKey {
    fn parse_legacy_compatible(value: &str) -> Result<pkarr::PublicKey, ParseError> {
        let raw = value
            .strip_prefix("pubky")
            .filter(|_| Self::is_pubky_prefixed(value));
        pkarr::PublicKey::try_from(raw.unwrap_or(value).to_string())
    }

    /// Returns true if the value is in the legacy `pubky<z32>` form.
    pub fn is_pubky_prefixed(value: &str) -> bool {
        matches!(value.strip_prefix("pubky"), Some(stripped) if stripped.len() == 52)
    }

    /// Borrow the inner [`pkarr::PublicKey`].
    #[must_use]
    pub const fn as_inner(&self) -> &pkarr::PublicKey {
        &self.0
    }

    /// Extract the inner [`pkarr::PublicKey`].
    #[must_use]
    pub fn into_inner(self) -> pkarr::PublicKey {
        self.0
    }

    /// Return the canonical z-base32 representation.
    ///
    /// This is the canonical transport/storage form used for hostnames, query
    /// parameters, serde, and database persistence.
    #[must_use]
    pub fn z32(&self) -> String {
        self.0.to_string()
    }

    /// Parse a public key from raw z-base32 text (without the `pubky` prefix).
    pub fn try_from_z32(value: &str) -> Result<Self, ParseError> {
        pkarr::PublicKey::try_from(value.to_string()).map(Self)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.z32())
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PublicKey").field(&self.to_string()).finish()
    }
}

impl Serialize for PublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.z32())
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if deserializer.is_human_readable() {
            let value = String::deserialize(deserializer)?;
            Self::try_from_z32(&value).map_err(serde::de::Error::custom)
        } else {
            pkarr::PublicKey::deserialize(deserializer).map(Self)
        }
    }
}

impl Deref for PublicKey {
    type Target = pkarr::PublicKey;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<pkarr::PublicKey> for PublicKey {
    fn from(value: pkarr::PublicKey) -> Self {
        Self(value)
    }
}

impl From<&pkarr::PublicKey> for PublicKey {
    fn from(value: &pkarr::PublicKey) -> Self {
        Self(value.clone())
    }
}

impl From<PublicKey> for pkarr::PublicKey {
    fn from(value: PublicKey) -> Self {
        value.0
    }
}

impl From<&PublicKey> for pkarr::PublicKey {
    fn from(value: &PublicKey) -> Self {
        value.0.clone()
    }
}

impl TryFrom<&str> for PublicKey {
    type Error = ParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::parse_legacy_compatible(value).map(Self)
    }
}

impl TryFrom<&String> for PublicKey {
    type Error = ParseError;

    fn try_from(value: &String) -> Result<Self, Self::Error> {
        Self::parse_legacy_compatible(value).map(Self)
    }
}

impl TryFrom<String> for PublicKey {
    type Error = ParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::parse_legacy_compatible(&value).map(Self)
    }
}

impl FromStr for PublicKey {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_legacy_compatible(s).map(Self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_key_serializes_as_z32() {
        let public_key = Keypair::random().public_key();

        let json = serde_json::to_string(&public_key).unwrap();

        assert_eq!(json, format!("\"{}\"", public_key.z32()));
    }

    #[test]
    fn public_key_deserializes_from_z32() {
        let public_key = Keypair::random().public_key();
        let json = format!("\"{}\"", public_key.z32());

        let parsed: PublicKey = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed, public_key);
    }

    #[test]
    fn public_key_display_uses_z32() {
        let public_key = Keypair::random().public_key();

        assert_eq!(public_key.to_string(), public_key.z32());
    }

    #[test]
    fn public_key_parses_legacy_prefixed_input() {
        let public_key = Keypair::random().public_key();
        let legacy = format!("pubky{public_key}");

        assert_eq!(legacy.parse::<PublicKey>().unwrap(), public_key);
    }
}

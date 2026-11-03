use percent_encoding::percent_decode_str;
use pubky_common::{crypto::PublicKey, StoragePathError};
use std::str::FromStr;

use super::StoragePath;

#[derive(thiserror::Error, Debug)]
pub enum EntryPathError {
    #[error("{0}")]
    Invalid(String),
    #[error("Failed to parse storage path: {0}")]
    InvalidStoragePath(StoragePathError),
    #[error("Failed to parse pubkey: {0}")]
    InvalidPubkey(pkarr::errors::PublicKeyError),
}

/// A path to an entry.
///
/// `FromStr` and `Display` use decoded storage keys (`<owner>/<path>`),
/// where percent signs are literal. Use the explicit URL methods for encoding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntryPath {
    pubkey: PublicKey,
    path: StoragePath,
    /// The key of the entry represented as a string.
    /// The key is the pubkey and the path concatenated.
    /// Example: `8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo/folder/file.txt`
    /// This is cached/redundant to avoid reallocating the string on every access.
    key: String,
}

impl EntryPath {
    pub fn new(pubkey: PublicKey, path: StoragePath) -> Self {
        let key = format!("{}{}", pubkey.z32(), path);
        Self { pubkey, path, key }
    }

    pub fn pubkey(&self) -> &PublicKey {
        &self.pubkey
    }

    pub fn path(&self) -> &StoragePath {
        &self.path
    }

    /// Render as a `pubky://` URL with a percent-encoded path.
    pub fn to_pubky_url(&self) -> String {
        format!("pubky://{}{}", self.pubkey.z32(), self.path.url_encode())
    }

    /// Parse a `pubky://<owner>/<path>` URL, decoding its path exactly once.
    /// Query strings and fragments are not supported; encode literal `?` and `#`.
    /// Dot segments are rejected rather than normalized.
    pub fn from_pubky_url(url: &str) -> Result<Self, EntryPathError> {
        let resource = url
            .strip_prefix("pubky://")
            .ok_or_else(|| EntryPathError::Invalid("expected a pubky:// URL".to_string()))?;
        if resource.contains(['?', '#']) {
            return Err(EntryPathError::Invalid(
                "resource URL cannot contain a query or fragment".to_string(),
            ));
        }
        let path_start = resource
            .find('/')
            .ok_or_else(|| EntryPathError::Invalid("Missing '/'".to_string()))?;
        let (owner, path) = resource.split_at(path_start);
        if PublicKey::is_pubky_prefixed(owner) {
            return Err(EntryPathError::Invalid(
                "unexpected `pubky` prefix; expected raw z32".to_string(),
            ));
        }
        let owner = PublicKey::try_from_z32(owner).map_err(EntryPathError::InvalidPubkey)?;
        let decoded_path = percent_decode_str(path).decode_utf8().map_err(|_| {
            EntryPathError::Invalid("resource URL path is not valid UTF-8".to_string())
        })?;
        let path = StoragePath::new(&decoded_path).map_err(EntryPathError::InvalidStoragePath)?;
        Ok(Self::new(owner, path))
    }

    /// The key of the entry.
    ///
    /// The key is the pubkey and the path concatenated.
    ///
    /// Example: `8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo/folder/file.txt`
    pub fn as_str(&self) -> &str {
        &self.key
    }

    /// Parse a path string into an `EntryPath`, returning an [`opendal::Error`]
    /// on failure. Convenience wrapper for use inside OpenDAL layers where the
    /// trait methods receive `&str` and must return `opendal::Result`.
    pub fn parse_opendal(path: &str) -> Result<Self, opendal::Error> {
        path.parse().map_err(|e: EntryPathError| {
            opendal::Error::new(opendal::ErrorKind::Unexpected, e.to_string())
        })
    }
}

impl AsRef<str> for EntryPath {
    fn as_ref(&self) -> &str {
        &self.key
    }
}

impl FromStr for EntryPath {
    type Err = EntryPathError;

    fn from_str(s: &str) -> Result<Self, EntryPathError> {
        let first_slash_index = s
            .find('/')
            .ok_or(EntryPathError::Invalid("Missing '/'".to_string()))?;
        let (pubkey, path) = match s.split_at_checked(first_slash_index) {
            Some((pubkey, path)) => (pubkey, path),
            None => return Err(EntryPathError::Invalid("Missing '/'".to_string())),
        };
        if PublicKey::is_pubky_prefixed(pubkey) {
            return Err(EntryPathError::Invalid(
                "unexpected `pubky` prefix; expected raw z32".to_string(),
            ));
        }
        let pubkey = PublicKey::try_from_z32(pubkey).map_err(EntryPathError::InvalidPubkey)?;
        let storage_path = StoragePath::new(path).map_err(EntryPathError::InvalidStoragePath)?;
        Ok(Self::new(pubkey, storage_path))
    }
}

impl std::fmt::Display for EntryPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

impl serde::Serialize for EntryPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_ref())
    }
}

impl<'de> serde::Deserialize<'de> for EntryPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pubky_common::storage_path::MAX_STORAGE_PATH_TOTAL_LENGTH;

    #[test]
    fn pubky_url_round_trip_preserves_decoded_storage_key() {
        let owner = "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo";
        let key = format!("{owner}/pub/a b%20#?ü/%%2E%%2E.txt");
        let entry: EntryPath = key.parse().unwrap();
        let url = format!("pubky://{owner}/pub/a%20b%2520%23%3F%C3%BC/%25%252E%25%252E.txt");
        assert_eq!(entry.to_pubky_url(), url);
        assert_eq!(EntryPath::from_pubky_url(&url).unwrap(), entry);
        assert_eq!(entry.to_string(), key);
    }

    #[test]
    fn pubky_url_rejects_invalid_components_and_decoded_paths() {
        let owner = "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo";
        for url in [
            format!("https://{owner}/pub/file"),
            format!("{owner}/pub/file"),
            format!("pubky://{owner}"),
            "pubky://invalid/pub/file".to_string(),
            format!("pubky://{owner}/pub/file?query"),
            format!("pubky://{owner}/pub/file#fragment"),
            format!("pubky://{owner}/pub/%FF"),
            format!("pubky://{owner}/pub/%2E%2E/file"),
            format!("pubky://{owner}/pub/../file"),
        ] {
            EntryPath::from_pubky_url(&url).unwrap_err();
        }
    }

    #[test]
    fn test_entry_path_from_str() {
        let pubkey =
            PublicKey::from_str("8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo").unwrap();
        let path = StoragePath::new("/pub/folder/file.txt").unwrap();
        let key = format!("{}{path}", pubkey.z32());
        let entry_path = EntryPath::new(pubkey, path);
        assert_eq!(entry_path.as_ref(), key);
    }

    #[test]
    fn test_entry_path_serde() {
        let string = "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo/pub/folder/file.txt";
        let entry_path = EntryPath::from_str(string).unwrap();
        assert_eq!(entry_path.to_string(), string);
    }

    #[test]
    fn maximum_storage_path_fits_storage_object_key_limit() {
        let pubkey =
            PublicKey::from_str("8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo").unwrap();
        let path = StoragePath::new(&"/a".repeat(MAX_STORAGE_PATH_TOTAL_LENGTH / 2)).unwrap();
        let entry_path = EntryPath::new(pubkey, path);

        assert_eq!(entry_path.as_str().len(), 1024);
    }
}

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
/// The path as a string is used to identify the entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntryPath {
    #[allow(dead_code)]
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

    #[allow(dead_code)]
    pub fn pubkey(&self) -> &PublicKey {
        &self.pubkey
    }

    pub fn path(&self) -> &StoragePath {
        &self.path
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

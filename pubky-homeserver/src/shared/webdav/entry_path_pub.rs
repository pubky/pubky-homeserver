use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::constants::PUBLIC_ROOT;

use super::EntryPath;

/// A path to an entry that requires the leading `/pub/` segment.
#[derive(Debug, Clone)]
pub struct EntryPathPub(pub EntryPath);

impl EntryPathPub {
    pub fn inner(&self) -> &EntryPath {
        &self.0
    }
}

impl std::fmt::Display for EntryPathPub {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner().as_str())
    }
}

impl FromStr for EntryPathPub {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let inner = EntryPath::from_str(s)?;
        if !inner.path().as_str().starts_with(PUBLIC_ROOT) {
            return Err(anyhow::anyhow!("Path must start with {PUBLIC_ROOT}"));
        }
        Ok(Self(inner))
    }
}

impl Serialize for EntryPathPub {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for EntryPathPub {
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

    #[test]
    fn test_entry_path_from_str() {
        EntryPathPub::from_str(
            "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo/pub/folder/file.txt",
        )
        .unwrap();
        EntryPathPub::from_str(
            "8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo/folder/file.txt",
        )
        .expect_err("Should not be valid. /pub/ required.");
    }
}

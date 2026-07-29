use std::str::FromStr;

use serde::{Deserialize, Serialize};

use super::StoragePath;

/// A webdav path that can be used with axum.
///
/// When using `.route("/{*path}", your_handler)` in axum, the path is passed without the leading slash.
/// This struct adds the leading slash back and therefore allows direct validation of the path.
///
/// This does **not** require any particular root prefix — use it when the storage-root
/// (`/pub/`, `/priv/`) requirement is an authorization concern enforced separately (so
/// violations can return 403 with a meaningful message instead of axum's default 400).
///
/// Usage in handler:
///
/// `Path(path): Path<WebDavPathAxum>`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WebDavPathAxum(StoragePath);

impl WebDavPathAxum {
    pub fn inner(&self) -> &StoragePath {
        &self.0
    }
}

impl std::fmt::Display for WebDavPathAxum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.as_str())
    }
}

impl FromStr for WebDavPathAxum {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let with_slash = format!("/{}", s);
        let inner = StoragePath::normalize(&with_slash)?;
        Ok(Self(inner))
    }
}

impl Serialize for WebDavPathAxum {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for WebDavPathAxum {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(serde::de::Error::custom)
    }
}

/// A WebDAV file path that can be used with axum.
///
/// This has the same path normalization behavior as [`WebDavPathAxum`], but
/// rejects directory-shaped paths. It does not enforce any storage root; root
/// and capability checks remain authorization concerns.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WebDavFilePathAxum(WebDavPathAxum);

impl WebDavFilePathAxum {
    pub fn inner(&self) -> &StoragePath {
        self.0.inner()
    }
}

impl std::fmt::Display for WebDavFilePathAxum {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for WebDavFilePathAxum {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        WebDavPathAxum::from_str(s)?.try_into()
    }
}

impl TryFrom<WebDavPathAxum> for WebDavFilePathAxum {
    type Error = anyhow::Error;

    fn try_from(path: WebDavPathAxum) -> Result<Self, Self::Error> {
        anyhow::ensure!(path.inner().is_file(), "target path must be a file");

        Ok(Self(path))
    }
}

impl Serialize for WebDavFilePathAxum {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for WebDavFilePathAxum {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let path = WebDavPathAxum::deserialize(deserializer)?;
        Self::try_from(path).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adds_leading_slash() {
        let path = WebDavPathAxum::from_str("foo/bar").unwrap();
        assert_eq!(path.inner().as_str(), "/foo/bar");
    }

    #[test]
    fn accepts_non_pub_paths() {
        // The storage-root requirement does not apply here, it is enforced in authz.
        WebDavPathAxum::from_str("priv/file.txt").expect("Should be valid");
        WebDavPathAxum::from_str("pub/file.txt").expect("Should be valid");
    }

    #[test]
    fn file_path_adds_leading_slash() {
        let path = WebDavFilePathAxum::from_str("foo/bar.txt").unwrap();
        assert_eq!(path.inner().as_str(), "/foo/bar.txt");
    }

    #[test]
    fn file_path_rejects_directory_paths() {
        WebDavFilePathAxum::from_str("foo/bar/").expect_err("directory path should be rejected");
    }

    #[test]
    fn file_path_accepts_non_pub_paths() {
        WebDavFilePathAxum::from_str("priv/file.txt").expect("priv file path should be valid");
        WebDavFilePathAxum::from_str("other/file.txt")
            .expect("root validation should remain an authorization concern");
    }
}

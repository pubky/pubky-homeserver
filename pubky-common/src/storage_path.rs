//! Canonical decoded paths used by Pubky storage and WebDAV operations.

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

/// Maximum decoded UTF-8 byte length of one path segment.
pub const MAX_STORAGE_PATH_SEGMENT_LENGTH: usize = 255;
/// Maximum decoded UTF-8 byte length of a complete canonical path.
///
/// This leaves room for the 52-byte z32 tenant key in a 1024-byte storage object key.
/// This contraint is enforced by the storage backend, so we enforce it here to avoid creating invalid paths.
pub const MAX_STORAGE_PATH_TOTAL_LENGTH: usize = 972;

/// A canonical decoded Pubky storage path that can be encoded as an HTTP/WebDAV URI path.
///
/// Percent signs are literal. URL decoding must happen before construction.
/// Paths cannot end in whitespace because storage backends may trim it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct StoragePath(String);

impl StoragePath {
    /// Parse an already-canonical decoded absolute path.
    pub fn new(path: &str) -> Result<Self, StoragePathError> {
        validate_canonical(path)?;
        Ok(Self(path.to_string()))
    }

    /// Normalize a decoded absolute HTTP/WebDAV path and validate the result.
    pub fn normalize(path: &str) -> Result<Self, StoragePathError> {
        if !path.starts_with('/') {
            return Err(StoragePathError::NotAbsolute);
        }

        let directory_shaped =
            path.ends_with('/') || matches!(path.rsplit('/').next(), Some(".") | Some(".."));
        let mut segments = Vec::new();

        for segment in path.split('/').skip(1) {
            match segment {
                "" | "." => {}
                ".." => {
                    segments.pop().ok_or(StoragePathError::TraversalAboveRoot)?;
                }
                _ => {
                    validate_segment(segment)?;
                    segments.push(segment);
                }
            }
        }

        let mut canonical = String::from("/");
        canonical.push_str(&segments.join("/"));
        if directory_shaped && canonical != "/" {
            canonical.push('/');
        }

        validate_total_length(&canonical)?;
        validate_trailing_whitespace(&canonical)?;
        Ok(Self(canonical))
    }

    /// Borrow the decoded canonical path.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Return whether this path is the storage root.
    pub fn is_root(&self) -> bool {
        self.0 == "/"
    }

    /// Return whether this path is directory-shaped.
    pub fn is_directory(&self) -> bool {
        self.0.ends_with('/')
    }

    /// Return whether this path is file-shaped.
    pub fn is_file(&self) -> bool {
        !self.is_directory()
    }

    /// Encode this decoded path for use as an HTTP URL path.
    pub fn url_encode(&self) -> String {
        percent_encoding::utf8_percent_encode(self.as_str(), PATH_ENCODE_SET).to_string()
    }
}

impl AsRef<str> for StoragePath {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for StoragePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for StoragePath {
    type Err = StoragePathError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        Self::new(path)
    }
}

impl TryFrom<&str> for StoragePath {
    type Error = StoragePathError;

    fn try_from(path: &str) -> Result<Self, Self::Error> {
        Self::new(path)
    }
}

impl TryFrom<String> for StoragePath {
    type Error = StoragePathError;

    fn try_from(path: String) -> Result<Self, Self::Error> {
        Self::new(&path)
    }
}

impl Serialize for StoragePath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for StoragePath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let path = String::deserialize(deserializer)?;
        Self::new(&path).map_err(serde::de::Error::custom)
    }
}

/// Error validating or normalizing a [`StoragePath`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoragePathError {
    /// The path does not begin with `/`.
    #[error("path must be absolute")]
    NotAbsolute,
    /// The path contains an empty segment such as `//`.
    #[error("path contains an empty segment")]
    EmptySegment,
    /// The path contains a `.` segment.
    #[error("path contains a `.` segment")]
    CurrentDirectorySegment,
    /// The path contains a `..` segment.
    #[error("path contains a `..` segment")]
    ParentDirectorySegment,
    /// Normalization would traverse above root.
    #[error("path traverses above root")]
    TraversalAboveRoot,
    /// A segment contains a Unicode control character.
    #[error("path contains a control character")]
    ControlCharacter,
    /// A segment contains a backslash, which is a path separator on some platforms.
    #[error("path must not contain a backslash")]
    Backslash,
    /// The complete path ends in Unicode whitespace.
    #[error("path must not end in whitespace")]
    TrailingWhitespace,
    /// A decoded segment exceeds the byte limit.
    #[error("path segment is {actual} bytes; maximum is {maximum}")]
    SegmentTooLong {
        /// Actual decoded UTF-8 byte length.
        actual: usize,
        /// Maximum decoded UTF-8 byte length.
        maximum: usize,
    },
    /// The complete decoded path exceeds the byte limit.
    #[error("path is {actual} bytes; maximum is {maximum}")]
    PathTooLong {
        /// Actual decoded UTF-8 byte length.
        actual: usize,
        /// Maximum decoded UTF-8 byte length.
        maximum: usize,
    },
}

const PATH_ENCODE_SET: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~')
    .remove(b'/');

fn validate_canonical(path: &str) -> Result<(), StoragePathError> {
    if !path.starts_with('/') {
        return Err(StoragePathError::NotAbsolute);
    }
    validate_total_length(path)?;
    if path == "/" {
        return Ok(());
    }

    let without_root = &path[1..];
    let segments = without_root.split('/').collect::<Vec<_>>();
    let last_index = segments.len() - 1;

    for (index, segment) in segments.into_iter().enumerate() {
        if segment.is_empty() {
            if index == last_index {
                continue;
            }
            return Err(StoragePathError::EmptySegment);
        }
        match segment {
            "." => return Err(StoragePathError::CurrentDirectorySegment),
            ".." => return Err(StoragePathError::ParentDirectorySegment),
            _ => validate_segment(segment)?,
        }
    }

    validate_trailing_whitespace(path)?;
    Ok(())
}

fn validate_segment(segment: &str) -> Result<(), StoragePathError> {
    if segment.len() > MAX_STORAGE_PATH_SEGMENT_LENGTH {
        return Err(StoragePathError::SegmentTooLong {
            actual: segment.len(),
            maximum: MAX_STORAGE_PATH_SEGMENT_LENGTH,
        });
    }
    if segment.chars().any(char::is_control) {
        return Err(StoragePathError::ControlCharacter);
    }
    if segment.contains('\\') {
        return Err(StoragePathError::Backslash);
    }
    Ok(())
}

fn validate_total_length(path: &str) -> Result<(), StoragePathError> {
    if path.len() > MAX_STORAGE_PATH_TOTAL_LENGTH {
        return Err(StoragePathError::PathTooLong {
            actual: path.len(),
            maximum: MAX_STORAGE_PATH_TOTAL_LENGTH,
        });
    }
    Ok(())
}

fn validate_trailing_whitespace(path: &str) -> Result<(), StoragePathError> {
    if path.chars().last().is_some_and(char::is_whitespace) {
        return Err(StoragePathError::TrailingWhitespace);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_parser_accepts_canonical_decoded_paths() {
        for path in [
            "/",
            "/pub/file.txt",
            "/priv/app/",
            "/pub/My File/über",
            "/pub/My%20File/%C3%BCber",
            "/pub/a:b,c",
            "/a..",
            "/.hidden",
            "/...",
            "/%2E/%2E%2E/%2F",
        ] {
            assert_eq!(StoragePath::new(path).unwrap().as_str(), path);
        }
    }

    #[test]
    fn strict_parser_reports_exact_noncanonical_error() {
        for (path, expected) in [
            ("", StoragePathError::NotAbsolute),
            ("relative", StoragePathError::NotAbsolute),
            ("//", StoragePathError::EmptySegment),
            ("/a//b", StoragePathError::EmptySegment),
            ("/a//", StoragePathError::EmptySegment),
            ("///", StoragePathError::EmptySegment),
            ("/.", StoragePathError::CurrentDirectorySegment),
            ("/a/./", StoragePathError::CurrentDirectorySegment),
            ("/..", StoragePathError::ParentDirectorySegment),
            ("/a/../b", StoragePathError::ParentDirectorySegment),
        ] {
            assert_eq!(StoragePath::new(path), Err(expected), "{path}");
        }
    }

    #[test]
    fn normalizer_handles_webdav_aliases() {
        for (input, expected) in [
            ("/", "/"),
            ("//", "/"),
            ("/a//b", "/a/b"),
            ("/a///b/", "/a/b/"),
            ("/.", "/"),
            ("/a/.", "/a/"),
            ("/a/b/..", "/a/"),
            ("/a/b/../c", "/a/c"),
            ("/a/..", "/"),
            ("/a/../", "/"),
            ("/a/b/../..", "/"),
            ("/a/..//b", "/b"),
            ("/a/name..", "/a/name.."),
            ("/.hidden/...", "/.hidden/..."),
            ("/a/%2E%2E/b", "/a/%2E%2E/b"),
            ("///", "/"),
        ] {
            let normalized = StoragePath::normalize(input).unwrap();
            assert_eq!(normalized.as_str(), expected, "{input}");
            assert_eq!(
                StoragePath::new(normalized.as_str()),
                Ok(normalized.clone())
            );
            assert_eq!(StoragePath::normalize(normalized.as_str()), Ok(normalized));
        }
    }

    #[test]
    fn normalizer_reports_input_and_traversal_errors() {
        for path in ["", "relative"] {
            assert_eq!(
                StoragePath::normalize(path),
                Err(StoragePathError::NotAbsolute)
            );
        }

        for path in ["/..", "/./..", "/a/../..", "/a/../../b"] {
            assert_eq!(
                StoragePath::normalize(path),
                Err(StoragePathError::TraversalAboveRoot)
            );
        }
    }

    #[test]
    fn rejects_ascii_and_unicode_controls() {
        for path in ["/a\nb", "/a\0b", "/a\u{85}b"] {
            assert_eq!(
                StoragePath::new(path),
                Err(StoragePathError::ControlCharacter)
            );
            assert_eq!(
                StoragePath::normalize(path),
                Err(StoragePathError::ControlCharacter)
            );
        }

        assert_eq!(
            StoragePath::normalize("/a\nb/.."),
            Err(StoragePathError::ControlCharacter)
        );
    }

    #[test]
    fn rejects_backslashes() {
        for path in ["/a\\b", "/pub/app/\\..\\secret", "/a\\b/.."] {
            assert_eq!(
                StoragePath::new(path),
                Err(StoragePathError::Backslash),
                "{path:?}"
            );
            assert_eq!(
                StoragePath::normalize(path),
                Err(StoragePathError::Backslash),
                "{path:?}"
            );
        }
    }

    #[test]
    fn rejects_trailing_unicode_whitespace() {
        for path in ["/a ", "/a\u{a0}", "/a\u{3000}"] {
            assert_eq!(
                StoragePath::new(path),
                Err(StoragePathError::TrailingWhitespace),
                "{path:?}"
            );
            assert_eq!(
                StoragePath::normalize(path),
                Err(StoragePathError::TrailingWhitespace),
                "{path:?}"
            );
        }

        for path in ["/My File", "/ leading", "/directory /file"] {
            assert!(StoragePath::new(path).is_ok(), "{path:?}");
            assert!(StoragePath::normalize(path).is_ok(), "{path:?}");
        }
    }

    #[test]
    fn enforces_decoded_segment_byte_limit() {
        let ascii_maximum = format!("/{}", "a".repeat(MAX_STORAGE_PATH_SEGMENT_LENGTH));
        assert!(StoragePath::new(&ascii_maximum).is_ok());
        assert!(StoragePath::normalize(&ascii_maximum).is_ok());

        let ascii_oversized = format!("{ascii_maximum}a");
        let expected = Err(StoragePathError::SegmentTooLong {
            actual: MAX_STORAGE_PATH_SEGMENT_LENGTH + 1,
            maximum: MAX_STORAGE_PATH_SEGMENT_LENGTH,
        });
        assert_eq!(StoragePath::new(&ascii_oversized), expected);
        assert_eq!(StoragePath::normalize(&ascii_oversized), expected);
        assert_eq!(
            StoragePath::normalize(&format!("{ascii_oversized}/..")),
            expected
        );

        let multibyte_limit = format!("/{}a", "é".repeat(127));
        assert_eq!(multibyte_limit.len(), 256);
        assert!(StoragePath::new(&multibyte_limit).is_ok());
        assert!(StoragePath::normalize(&multibyte_limit).is_ok());

        let multibyte_oversized = format!("/{}", "é".repeat(128));
        assert_eq!(StoragePath::new(&multibyte_oversized), expected);
        assert_eq!(StoragePath::normalize(&multibyte_oversized), expected);
    }

    #[test]
    fn enforces_total_decoded_byte_limit() {
        let maximum = "/a".repeat(MAX_STORAGE_PATH_TOTAL_LENGTH / 2);
        assert_eq!(maximum.len(), MAX_STORAGE_PATH_TOTAL_LENGTH);
        assert!(StoragePath::new(&maximum).is_ok());
        assert!(StoragePath::normalize(&maximum).is_ok());

        let oversized = format!("{maximum}b");
        let expected = Err(StoragePathError::PathTooLong {
            actual: MAX_STORAGE_PATH_TOTAL_LENGTH + 1,
            maximum: MAX_STORAGE_PATH_TOTAL_LENGTH,
        });
        assert_eq!(StoragePath::new(&oversized), expected);
        assert_eq!(StoragePath::normalize(&oversized), expected);
    }

    #[test]
    fn strict_parser_reports_errors_in_validation_order() {
        let oversized_with_empty_segment =
            format!("//{}", "a".repeat(MAX_STORAGE_PATH_TOTAL_LENGTH));
        assert_eq!(
            oversized_with_empty_segment.len(),
            MAX_STORAGE_PATH_TOTAL_LENGTH + 2
        );
        assert_eq!(
            StoragePath::new(&oversized_with_empty_segment),
            Err(StoragePathError::PathTooLong {
                actual: MAX_STORAGE_PATH_TOTAL_LENGTH + 2,
                maximum: MAX_STORAGE_PATH_TOTAL_LENGTH,
            })
        );

        let oversized_segment_with_control = format!("/{}\n", "a".repeat(255));
        assert_eq!(
            StoragePath::new(&oversized_segment_with_control),
            Err(StoragePathError::SegmentTooLong {
                actual: 256,
                maximum: MAX_STORAGE_PATH_SEGMENT_LENGTH,
            })
        );
    }

    #[test]
    fn classifies_root_file_and_directory_paths() {
        for (value, is_root, is_directory, is_file) in [
            ("/", true, true, false),
            ("/a", false, false, true),
            ("/a/", false, true, false),
        ] {
            let path = StoragePath::new(value).unwrap();
            assert_eq!(path.is_root(), is_root, "{value}");
            assert_eq!(path.is_directory(), is_directory, "{value}");
            assert_eq!(path.is_file(), is_file, "{value}");
            assert_eq!(path.as_ref(), value);
            assert_eq!(path.to_string(), value);
        }
    }

    #[test]
    fn url_encoding_preserves_literal_percent_semantics() {
        let decoded = StoragePath::new("/pub/My%20 File/über").unwrap();
        assert_eq!(decoded.url_encode(), "/pub/My%2520%20File/%C3%BCber");
    }

    #[test]
    fn url_encoding_preserves_only_path_separators_and_unreserved_characters() {
        let decoded = StoragePath::new("/AZaz09-._~/:,?#@/%").unwrap();
        assert_eq!(decoded.url_encode(), "/AZaz09-._~/%3A%2C%3F%23%40/%25");
        assert_eq!(StoragePath::new("/").unwrap().url_encode(), "/");
        assert_eq!(StoragePath::new("/a/").unwrap().url_encode(), "/a/");
    }

    #[test]
    fn conversion_traits_are_strict() {
        let expected = StoragePath::new("/a/").unwrap();
        assert_eq!("/a/".parse::<StoragePath>(), Ok(expected.clone()));
        assert_eq!(StoragePath::try_from("/a/"), Ok(expected.clone()));
        assert_eq!(StoragePath::try_from(String::from("/a/")), Ok(expected));

        for result in [
            "/a//b".parse::<StoragePath>(),
            StoragePath::try_from("/a//b"),
            StoragePath::try_from(String::from("/a//b")),
        ] {
            assert_eq!(result, Err(StoragePathError::EmptySegment));
        }
    }

    #[test]
    fn serde_is_exact_strict_and_round_trips() {
        let path = StoragePath::new("/pub/über%20").unwrap();
        let json = serde_json::to_string(&path).unwrap();
        assert_eq!(json, r#""/pub/über%20""#);
        assert_eq!(serde_json::from_str::<StoragePath>(&json).unwrap(), path);

        let escaped = StoragePath::new("/a\"b").unwrap();
        let json = serde_json::to_string(&escaped).unwrap();
        assert_eq!(json, r#""/a\"b""#);
        assert_eq!(serde_json::from_str::<StoragePath>(&json).unwrap(), escaped);

        for invalid in [
            r#""/pub//file""#,
            r#""/pub/./file""#,
            r#""/pub/a\\b""#,
            r#""relative""#,
        ] {
            assert!(serde_json::from_str::<StoragePath>(invalid).is_err());
        }
        for non_string in ["null", "123", "[]", "{}"] {
            assert!(serde_json::from_str::<StoragePath>(non_string).is_err());
        }
    }
}

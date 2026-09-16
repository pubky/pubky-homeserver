//! Entity-tag preconditions for storage writes (`If-Match`, `If-None-Match`).
//!
//! Semantics follow RFC 9110 §13.1.1 and §13.1.2: `If-Match` uses strong
//! comparison, `If-None-Match` uses weak comparison, and `If-Match` is
//! evaluated first. The "current" entity tag of a stored file is its content
//! hash, see [`content_hash_etag`](super::file::file_metadata::content_hash_etag).

use axum::http::{header, HeaderMap, HeaderName};
use pubky_common::crypto::Hash;

use super::file::file_metadata::content_hash_etag_value;

/// Preconditions attached to a storage write.
///
/// Travels from the HTTP route through OpenDAL's `OpWrite::if_match` /
/// `OpWrite::if_none_match` to the write finalization layer, which enforces it
/// against the entry table. See [`Self::if_match_header`] for the wire form.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WritePreconditions {
    if_match: Option<EntityTagList>,
    if_none_match: Option<EntityTagList>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PreconditionParseError {
    #[error("invalid If-Match header")]
    IfMatch,
    #[error("invalid If-None-Match header")]
    IfNoneMatch,
}

impl WritePreconditions {
    /// Parse the conditional headers of a request. Missing headers impose no condition.
    pub fn from_headers(headers: &HeaderMap) -> Result<Self, PreconditionParseError> {
        let if_match = joined_header(headers, header::IF_MATCH)
            .map_err(|()| PreconditionParseError::IfMatch)?;
        let if_none_match = joined_header(headers, header::IF_NONE_MATCH)
            .map_err(|()| PreconditionParseError::IfNoneMatch)?;
        Self::parse(if_match.as_deref(), if_none_match.as_deref())
    }

    /// Parse raw header values, as sent on the wire or as forwarded through OpenDAL.
    pub fn parse(
        if_match: Option<&str>,
        if_none_match: Option<&str>,
    ) -> Result<Self, PreconditionParseError> {
        Ok(Self {
            if_match: if_match
                .map(EntityTagList::parse)
                .transpose()
                .map_err(|()| PreconditionParseError::IfMatch)?,
            if_none_match: if_none_match
                .map(EntityTagList::parse)
                .transpose()
                .map_err(|()| PreconditionParseError::IfNoneMatch)?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.if_match.is_none() && self.if_none_match.is_none()
    }

    /// Canonical `If-Match` header value, for forwarding through OpenDAL.
    pub fn if_match_header(&self) -> Option<String> {
        self.if_match.as_ref().map(EntityTagList::to_header_value)
    }

    /// Canonical `If-None-Match` header value, for forwarding through OpenDAL.
    pub fn if_none_match_header(&self) -> Option<String> {
        self.if_none_match
            .as_ref()
            .map(EntityTagList::to_header_value)
    }

    /// Whether a write may proceed given the content hash of the file currently
    /// stored at the path, or `None` if nothing is stored there.
    pub fn is_satisfied_by(&self, current: Option<&Hash>) -> bool {
        let current = current.map(content_hash_etag_value);
        let current = current.as_deref();

        self.if_match
            .as_ref()
            .is_none_or(|list| list.if_match_passes(current))
            && self
                .if_none_match
                .as_ref()
                .is_none_or(|list| list.if_none_match_passes(current))
    }
}

/// Whether an `If-None-Match` request header matches the stored file, i.e. a
/// `GET` may answer `304 Not Modified` (RFC 9110 §13.1.2, weak comparison).
///
/// A malformed value never matches, so a read falls back to a full response
/// rather than failing; writes are stricter and reject malformed headers.
pub fn if_none_match_matches(raw: &str, current: &Hash) -> bool {
    let current = content_hash_etag_value(current);
    EntityTagList::parse(raw).is_ok_and(|list| !list.if_none_match_passes(Some(&current)))
}

/// A header may be sent several times; RFC 9110 §5.3 allows joining them with commas.
/// Errors if any value is not visible ASCII.
fn joined_header(headers: &HeaderMap, name: HeaderName) -> Result<Option<String>, ()> {
    let values = headers
        .get_all(name)
        .iter()
        .map(|value| value.to_str().map_err(|_| ()))
        .collect::<Result<Vec<_>, ()>>()?;
    Ok((!values.is_empty()).then(|| values.join(", ")))
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum EntityTagList {
    Any,
    Tags(Vec<EntityTag>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct EntityTag {
    weak: bool,
    opaque: String,
}

impl EntityTagList {
    fn parse(raw: &str) -> Result<Self, ()> {
        let raw = raw.trim();
        if raw == "*" {
            return Ok(Self::Any);
        }

        // `"` and `,` are not valid entity-tag characters, so splitting on
        // commas cannot split a tag. Empty list elements are permitted (§5.6.1).
        let tags = raw
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(EntityTag::parse)
            .collect::<Result<Vec<_>, ()>>()?;
        if tags.is_empty() {
            return Err(());
        }
        Ok(Self::Tags(tags))
    }

    fn to_header_value(&self) -> String {
        match self {
            Self::Any => "*".to_string(),
            Self::Tags(tags) => tags
                .iter()
                .map(EntityTag::to_header_value)
                .collect::<Vec<_>>()
                .join(", "),
        }
    }

    /// RFC 9110 §13.1.1: strong comparison, `*` requires the resource to exist.
    fn if_match_passes(&self, current: Option<&str>) -> bool {
        match self {
            Self::Any => current.is_some(),
            Self::Tags(tags) => current
                .is_some_and(|current| tags.iter().any(|tag| !tag.weak && tag.opaque == current)),
        }
    }

    /// RFC 9110 §13.1.2: weak comparison, `*` requires the resource to be absent.
    fn if_none_match_passes(&self, current: Option<&str>) -> bool {
        match self {
            Self::Any => current.is_none(),
            Self::Tags(tags) => {
                current.is_none_or(|current| tags.iter().all(|tag| tag.opaque != current))
            }
        }
    }
}

impl EntityTag {
    fn parse(item: &str) -> Result<Self, ()> {
        let (weak, quoted) = match item.strip_prefix("W/") {
            Some(rest) => (true, rest),
            None => (false, item),
        };
        let opaque = quoted
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .ok_or(())?;
        let is_etagc = |byte: u8| byte == b'!' || (b'#'..=b'~').contains(&byte);
        if !opaque.bytes().all(is_etagc) {
            return Err(());
        }
        Ok(Self {
            weak,
            opaque: opaque.to_string(),
        })
    }

    fn to_header_value(&self) -> String {
        if self.weak {
            format!("W/\"{}\"", self.opaque)
        } else {
            format!("\"{}\"", self.opaque)
        }
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::super::file::file_metadata::content_hash_etag;
    use super::*;

    fn hash(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    fn preconditions(if_match: Option<&str>, if_none_match: Option<&str>) -> WritePreconditions {
        WritePreconditions::parse(if_match, if_none_match).unwrap()
    }

    #[test]
    fn no_headers_impose_no_condition() {
        let none = WritePreconditions::default();
        assert!(none.is_empty());
        assert!(none.is_satisfied_by(None));
        assert!(none.is_satisfied_by(Some(&hash(1))));
        assert_eq!(
            WritePreconditions::from_headers(&HeaderMap::new()).unwrap(),
            none
        );
    }

    #[test]
    fn if_match_uses_strong_comparison() {
        let current = hash(1);
        let matching = content_hash_etag(&current);

        assert!(preconditions(Some(&matching), None).is_satisfied_by(Some(&current)));
        assert!(preconditions(Some(&format!("\"other\", {matching}")), None)
            .is_satisfied_by(Some(&current)));
        assert!(
            !preconditions(Some(&format!("W/{matching}")), None).is_satisfied_by(Some(&current))
        );
        assert!(!preconditions(Some("\"other\""), None).is_satisfied_by(Some(&current)));
        assert!(!preconditions(Some(&matching), None).is_satisfied_by(None));
        assert!(preconditions(Some("*"), None).is_satisfied_by(Some(&current)));
        assert!(!preconditions(Some("*"), None).is_satisfied_by(None));
    }

    #[test]
    fn if_none_match_uses_weak_comparison() {
        let current = hash(2);
        let matching = content_hash_etag(&current);

        assert!(!preconditions(None, Some(&matching)).is_satisfied_by(Some(&current)));
        assert!(
            !preconditions(None, Some(&format!("W/{matching}"))).is_satisfied_by(Some(&current))
        );
        assert!(preconditions(None, Some("\"other\"")).is_satisfied_by(Some(&current)));
        assert!(preconditions(None, Some("\"other\"")).is_satisfied_by(None));
        assert!(!preconditions(None, Some("*")).is_satisfied_by(Some(&current)));
        assert!(preconditions(None, Some("*")).is_satisfied_by(None));
    }

    #[test]
    fn both_headers_must_pass() {
        let current = hash(3);
        let matching = content_hash_etag(&current);

        assert!(preconditions(Some(&matching), Some("\"other\"")).is_satisfied_by(Some(&current)));
        assert!(!preconditions(Some(&matching), Some(&matching)).is_satisfied_by(Some(&current)));
        assert!(
            !preconditions(Some("\"other\""), Some("\"other\"")).is_satisfied_by(Some(&current))
        );
    }

    #[test]
    fn rejects_malformed_headers() {
        assert_eq!(
            WritePreconditions::parse(Some("unquoted"), None).unwrap_err(),
            PreconditionParseError::IfMatch
        );
        assert_eq!(
            WritePreconditions::parse(None, Some("W/not-quoted")).unwrap_err(),
            PreconditionParseError::IfNoneMatch
        );
        WritePreconditions::parse(Some("*, \"tag\""), None).unwrap_err();
        WritePreconditions::parse(Some(""), None).unwrap_err();
        WritePreconditions::parse(Some("\"has space\""), None).unwrap_err();
        WritePreconditions::parse(Some("\"a\", W/\"b\", \"c\""), None).unwrap();
    }

    #[test]
    fn header_values_round_trip_through_canonical_form() {
        let parsed = preconditions(Some(" \"a\" ,W/\"b\",, \"c\""), Some("*"));
        assert_eq!(
            parsed.if_match_header().as_deref(),
            Some("\"a\", W/\"b\", \"c\"")
        );
        assert_eq!(parsed.if_none_match_header().as_deref(), Some("*"));
        assert_eq!(
            WritePreconditions::parse(
                parsed.if_match_header().as_deref(),
                parsed.if_none_match_header().as_deref()
            )
            .unwrap(),
            parsed
        );
    }

    #[test]
    fn if_none_match_matches_for_reads() {
        let current = hash(6);
        let matching = content_hash_etag(&current);

        assert!(if_none_match_matches(&matching, &current));
        assert!(if_none_match_matches(&format!("W/{matching}"), &current));
        assert!(if_none_match_matches(
            &format!("\"other\", {matching}"),
            &current
        ));
        assert!(if_none_match_matches("*", &current));
        assert!(!if_none_match_matches("\"other\"", &current));
        assert!(!if_none_match_matches("unquoted", &current));
    }

    #[test]
    fn repeated_headers_are_joined() {
        let current = hash(4);
        let mut headers = HeaderMap::new();
        headers.append(header::IF_MATCH, HeaderValue::from_static("\"first\""));
        headers.append(
            header::IF_MATCH,
            HeaderValue::from_str(&content_hash_etag(&current)).unwrap(),
        );

        let parsed = WritePreconditions::from_headers(&headers).unwrap();
        assert!(parsed.is_satisfied_by(Some(&current)));
        assert!(!parsed.is_satisfied_by(Some(&hash(5))));
    }
}

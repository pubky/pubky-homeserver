//! Entity-tag preconditions for storage `PUT` (`If-Match`, `If-None-Match`).
//!
//! Each header carries a single strong entity tag, or `*`. RFC 9110 also
//! allows lists and weak tags; those are rejected rather than interpreted, so
//! a client that sends them gets an error, never a silently unconditional
//! write. `If-Match` requires the stored content to carry the tag (or to
//! exist, for `*`); `If-None-Match` requires it not to (or not to exist).
//! The current entity tag of a stored file is its content hash, see
//! [`content_hash_etag`](super::file::file_metadata::content_hash_etag).

use axum::http::{header, HeaderMap, HeaderName};
use pubky_common::crypto::Hash;

use super::file::file_metadata::content_hash_etag_value;

/// Preconditions attached to a storage write.
///
/// Travels from the HTTP route through OpenDAL's `OpWrite::if_match` /
/// `OpWrite::if_none_match` to the write finalization layer, which enforces it
/// against the stored content. See [`Self::if_match_header`] for the wire form.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WritePreconditions {
    if_match: Option<Condition>,
    if_none_match: Option<Condition>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PreconditionParseError {
    #[error("invalid If-Match header: expected a single strong entity tag or `*`")]
    IfMatch,
    #[error("invalid If-None-Match header: expected a single strong entity tag or `*`")]
    IfNoneMatch,
}

impl WritePreconditions {
    /// Parse the conditional headers of a request. Missing headers impose no
    /// condition; a header sent more than once is invalid.
    pub fn from_headers(headers: &HeaderMap) -> Result<Self, PreconditionParseError> {
        let if_match = single_header(headers, header::IF_MATCH)
            .map_err(|()| PreconditionParseError::IfMatch)?;
        let if_none_match = single_header(headers, header::IF_NONE_MATCH)
            .map_err(|()| PreconditionParseError::IfNoneMatch)?;
        Self::parse(if_match, if_none_match)
    }

    /// Parse raw header values, as sent on the wire or as forwarded through OpenDAL.
    pub fn parse(
        if_match: Option<&str>,
        if_none_match: Option<&str>,
    ) -> Result<Self, PreconditionParseError> {
        Ok(Self {
            if_match: if_match
                .map(Condition::parse)
                .transpose()
                .map_err(|()| PreconditionParseError::IfMatch)?,
            if_none_match: if_none_match
                .map(Condition::parse)
                .transpose()
                .map_err(|()| PreconditionParseError::IfNoneMatch)?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.if_match.is_none() && self.if_none_match.is_none()
    }

    /// Canonical `If-Match` header value, for forwarding through OpenDAL.
    pub fn if_match_header(&self) -> Option<String> {
        self.if_match.as_ref().map(Condition::to_header_value)
    }

    /// Canonical `If-None-Match` header value, for forwarding through OpenDAL.
    pub fn if_none_match_header(&self) -> Option<String> {
        self.if_none_match.as_ref().map(Condition::to_header_value)
    }

    /// Whether a write may proceed given the content hash of the file currently
    /// stored at the path, or `None` if nothing is stored there.
    pub fn is_satisfied_by(&self, current: Option<&Hash>) -> bool {
        let current = current.map(content_hash_etag_value);
        let current = current.as_deref();

        let if_match_passes = match &self.if_match {
            None => true,
            Some(Condition::Any) => current.is_some(),
            Some(Condition::Tag(tag)) => current == Some(tag.as_str()),
        };
        let if_none_match_passes = match &self.if_none_match {
            None => true,
            Some(Condition::Any) => current.is_none(),
            Some(Condition::Tag(tag)) => current != Some(tag.as_str()),
        };
        if_match_passes && if_none_match_passes
    }
}

/// Whether an `If-None-Match` request header matches the stored file, i.e. a
/// `GET` may answer `304 Not Modified`.
///
/// A value this module does not accept never matches, so a read falls back to
/// a full response rather than failing; writes are stricter and reject it.
pub fn if_none_match_matches(raw: &str, current: &Hash) -> bool {
    match Condition::parse(raw) {
        Ok(Condition::Any) => true,
        Ok(Condition::Tag(tag)) => tag == content_hash_etag_value(current),
        Err(()) => false,
    }
}

/// The value of a header that must not be repeated. Errors on repetition or
/// a value that is not visible ASCII.
fn single_header(headers: &HeaderMap, name: HeaderName) -> Result<Option<&str>, ()> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    value.to_str().map(Some).map_err(|_| ())
}

/// A single condition: any current representation, or one strong entity tag
/// (its opaque value, without quotes).
#[derive(Clone, Debug, PartialEq, Eq)]
enum Condition {
    Any,
    Tag(String),
}

impl Condition {
    fn parse(raw: &str) -> Result<Self, ()> {
        let raw = raw.trim();
        if raw == "*" {
            return Ok(Self::Any);
        }
        let opaque = raw
            .strip_prefix('"')
            .and_then(|rest| rest.strip_suffix('"'))
            .ok_or(())?;
        // RFC 9110 §8.8.3: etagc = "!" / %x23-7E. This excludes `"` and `,`,
        // so a list can never parse as one tag.
        let is_etagc = |byte: u8| byte == b'!' || (b'#'..=b'~').contains(&byte);
        if opaque.is_empty() || !opaque.bytes().all(is_etagc) {
            return Err(());
        }
        Ok(Self::Tag(opaque.to_string()))
    }

    fn to_header_value(&self) -> String {
        match self {
            Self::Any => "*".to_string(),
            Self::Tag(opaque) => format!("\"{opaque}\""),
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
    fn if_match_requires_the_tag_or_any_content() {
        let current = hash(1);
        let matching = content_hash_etag(&current);

        assert!(preconditions(Some(&matching), None).is_satisfied_by(Some(&current)));
        assert!(!preconditions(Some("\"other\""), None).is_satisfied_by(Some(&current)));
        assert!(!preconditions(Some(&matching), None).is_satisfied_by(None));
        assert!(preconditions(Some("*"), None).is_satisfied_by(Some(&current)));
        assert!(!preconditions(Some("*"), None).is_satisfied_by(None));
    }

    #[test]
    fn if_none_match_requires_a_different_tag_or_no_content() {
        let current = hash(2);
        let matching = content_hash_etag(&current);

        assert!(!preconditions(None, Some(&matching)).is_satisfied_by(Some(&current)));
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

    /// Lists and weak tags are valid HTTP but not supported here; they are
    /// rejected rather than partially interpreted.
    #[test]
    fn rejects_lists_weak_tags_and_malformed_values() {
        assert_eq!(
            WritePreconditions::parse(Some("unquoted"), None).unwrap_err(),
            PreconditionParseError::IfMatch
        );
        assert_eq!(
            WritePreconditions::parse(None, Some("W/\"weak\"")).unwrap_err(),
            PreconditionParseError::IfNoneMatch
        );
        for bad in [
            "\"a\", \"b\"",
            "*, \"tag\"",
            "W/\"weak\"",
            "",
            "\"\"",
            "\"has space\"",
            "\"has\"quote\"",
        ] {
            assert!(
                WritePreconditions::parse(Some(bad), None).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn header_values_round_trip_through_canonical_form() {
        let parsed = preconditions(Some("  \"a\" "), Some("*"));
        assert_eq!(parsed.if_match_header().as_deref(), Some("\"a\""));
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
    fn a_repeated_header_is_rejected() {
        let mut headers = HeaderMap::new();
        headers.append(header::IF_MATCH, HeaderValue::from_static("\"first\""));
        headers.append(header::IF_MATCH, HeaderValue::from_static("\"second\""));
        assert_eq!(
            WritePreconditions::from_headers(&headers).unwrap_err(),
            PreconditionParseError::IfMatch
        );

        let mut headers = HeaderMap::new();
        headers.insert(header::IF_MATCH, HeaderValue::from_static("\"only\""));
        assert_eq!(
            WritePreconditions::from_headers(&headers).unwrap(),
            preconditions(Some("\"only\""), None)
        );
    }

    #[test]
    fn if_none_match_matches_for_reads() {
        let current = hash(6);
        let matching = content_hash_etag(&current);

        assert!(if_none_match_matches(&matching, &current));
        assert!(if_none_match_matches("*", &current));
        assert!(!if_none_match_matches("\"other\"", &current));
        // Unsupported forms never match, so the read is answered in full.
        assert!(!if_none_match_matches(&format!("W/{matching}"), &current));
        assert!(!if_none_match_matches(
            &format!("\"other\", {matching}"),
            &current
        ));
        assert!(!if_none_match_matches("unquoted", &current));
    }
}

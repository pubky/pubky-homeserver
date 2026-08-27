use axum::http::{header, HeaderMap, HeaderName};
use pubky_common::crypto::Hash;

use super::{file::file_metadata::content_hash_etag, FileIoError};

/// HTTP entity-tag preconditions attached to a storage write.
#[derive(Clone, Debug, Default)]
pub(crate) struct WritePreconditions {
    if_match: Option<EntityTagList>,
    if_none_match: Option<EntityTagList>,
}

impl WritePreconditions {
    pub(crate) fn from_headers(headers: &HeaderMap) -> Result<Self, &'static str> {
        let if_match_raw = joined_header_value(headers, header::IF_MATCH);
        let if_none_match_raw = joined_header_value(headers, header::IF_NONE_MATCH);
        Self::parse(if_match_raw.as_deref(), if_none_match_raw.as_deref())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.if_match.is_none() && self.if_none_match.is_none()
    }

    pub(crate) fn check(&self, current_hash: Option<&Hash>) -> Result<(), FileIoError> {
        let current_etag = current_hash.map(content_hash_etag);
        let current_opaque = current_etag.as_deref().map(|etag| {
            etag.as_bytes()
                .strip_prefix(b"\"")
                .and_then(|etag| etag.strip_suffix(b"\""))
                .expect("homeserver content hashes always produce quoted entity tags")
        });

        if self
            .if_match
            .as_ref()
            .is_some_and(|condition| !condition.if_match_passes(current_opaque))
        {
            return Err(FileIoError::PreconditionFailed);
        }

        if self
            .if_none_match
            .as_ref()
            .is_some_and(|condition| !condition.if_none_match_passes(current_opaque))
        {
            return Err(FileIoError::PreconditionFailed);
        }

        Ok(())
    }

    fn parse(
        if_match_raw: Option<&[u8]>,
        if_none_match_raw: Option<&[u8]>,
    ) -> Result<Self, &'static str> {
        let if_match = if_match_raw
            .map(parse_entity_tag_list)
            .transpose()
            .map_err(|_| "invalid If-Match header")?;
        let if_none_match = if_none_match_raw
            .map(parse_entity_tag_list)
            .transpose()
            .map_err(|_| "invalid If-None-Match header")?;

        Ok(Self {
            if_match,
            if_none_match,
        })
    }
}

#[derive(Clone, Debug)]
enum EntityTagList {
    Any,
    Tags(Vec<EntityTag>),
}

impl EntityTagList {
    fn if_match_passes(&self, current: Option<&[u8]>) -> bool {
        match self {
            Self::Any => current.is_some(),
            Self::Tags(tags) => current
                .is_some_and(|current| tags.iter().any(|tag| !tag.weak && tag.opaque == current)),
        }
    }

    fn if_none_match_passes(&self, current: Option<&[u8]>) -> bool {
        match self {
            Self::Any => current.is_none(),
            Self::Tags(tags) => {
                current.is_none_or(|current| tags.iter().all(|tag| tag.opaque != current))
            }
        }
    }
}

#[derive(Clone, Debug)]
struct EntityTag {
    weak: bool,
    opaque: Vec<u8>,
}

fn joined_header_value(headers: &HeaderMap, name: HeaderName) -> Option<Vec<u8>> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    let mut joined = first.as_bytes().to_vec();
    for value in values {
        joined.extend_from_slice(b", ");
        joined.extend_from_slice(value.as_bytes());
    }
    Some(joined)
}

fn parse_entity_tag_list(raw: &[u8]) -> Result<EntityTagList, ()> {
    let raw = trim_ows(raw);
    if raw == b"*" {
        return Ok(EntityTagList::Any);
    }

    let mut tags = Vec::new();
    let mut index = 0;
    loop {
        skip_ows(raw, &mut index);
        let weak = raw.get(index..index + 2) == Some(b"W/");
        if weak {
            index += 2;
        }
        if raw.get(index) != Some(&b'\"') {
            return Err(());
        }
        index += 1;
        let opaque_start = index;

        while let Some(byte) = raw.get(index) {
            if *byte == b'\"' {
                break;
            }
            if *byte != b'!' && !(b'#'..=b'~').contains(byte) && *byte < 0x80 {
                return Err(());
            }
            index += 1;
        }
        if raw.get(index) != Some(&b'\"') {
            return Err(());
        }
        tags.push(EntityTag {
            weak,
            opaque: raw[opaque_start..index].to_vec(),
        });
        index += 1;

        skip_ows(raw, &mut index);
        if index == raw.len() {
            return Ok(EntityTagList::Tags(tags));
        }
        if raw.get(index) != Some(&b',') {
            return Err(());
        }
        index += 1;
        if index == raw.len() {
            return Err(());
        }
    }
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(|byte| is_ows(*byte)) {
        value = &value[1..];
    }
    while value.last().is_some_and(|byte| is_ows(*byte)) {
        value = &value[..value.len() - 1];
    }
    value
}

fn skip_ows(value: &[u8], index: &mut usize) {
    while value.get(*index).is_some_and(|byte| is_ows(*byte)) {
        *index += 1;
    }
}

fn is_ows(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(byte: u8) -> Hash {
        Hash::from_bytes([byte; 32])
    }

    fn preconditions(if_match: Option<&str>, if_none_match: Option<&str>) -> WritePreconditions {
        WritePreconditions::parse(
            if_match.map(str::as_bytes),
            if_none_match.map(str::as_bytes),
        )
        .unwrap()
    }

    #[test]
    fn test_if_match_requires_matching_existing_resource() {
        let current = hash(1);
        let matching = content_hash_etag(&current);

        preconditions(Some(&matching), None)
            .check(Some(&current))
            .unwrap();
        preconditions(Some(&format!("\"other\", {matching}")), None)
            .check(Some(&current))
            .unwrap();
        preconditions(Some(&format!("W/{matching}")), None)
            .check(Some(&current))
            .unwrap_err();
        preconditions(Some(&matching), None)
            .check(None)
            .unwrap_err();
        preconditions(Some("\"other\""), None)
            .check(Some(&current))
            .unwrap_err();
        preconditions(Some("*"), None)
            .check(Some(&current))
            .unwrap();
    }

    #[test]
    fn test_if_none_match_rejects_matching_existing_resource() {
        let current = hash(2);
        let matching = content_hash_etag(&current);

        preconditions(None, Some(&matching))
            .check(Some(&current))
            .unwrap_err();
        preconditions(None, Some(&format!("W/{matching}")))
            .check(Some(&current))
            .unwrap_err();
        preconditions(None, Some("\"other\""))
            .check(Some(&current))
            .unwrap();
        preconditions(None, Some("\"other\"")).check(None).unwrap();
        preconditions(None, Some("*"))
            .check(Some(&current))
            .unwrap_err();
        preconditions(None, Some("*")).check(None).unwrap();
    }

    #[test]
    fn test_entity_tag_header_validation() {
        WritePreconditions::parse(Some(b"\"first\", W/\"second,tag\""), None).unwrap();
        WritePreconditions::parse(Some(b"unquoted"), None).unwrap_err();
        WritePreconditions::parse(None, Some(b"W/not-quoted")).unwrap_err();
        WritePreconditions::parse(Some(b"*, \"tag\""), None).unwrap_err();
    }

    #[test]
    fn test_entity_tag_header_accepts_obs_text() {
        let current = hash(3);
        let matching = content_hash_etag(&current);
        let mut header = b"\"\x80\", ".to_vec();
        header.extend_from_slice(matching.as_bytes());

        WritePreconditions::parse(Some(&header), None)
            .unwrap()
            .check(Some(&current))
            .unwrap();
    }
}

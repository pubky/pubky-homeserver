use pubky_common::crypto::{Hash, Hasher};

use base64::Engine;

/// Fallback content type if no content type is detected.
const DEFAULT_CONTENT_TYPE: &str = "application/octet-stream";

pub(crate) fn content_hash_etag(hash: &Hash) -> String {
    format!(
        "\"{}\"",
        base64::engine::general_purpose::STANDARD.encode(hash.as_bytes())
    )
}

/// Metadata of a file.
#[derive(Debug, Clone)]
pub struct FileMetadata {
    pub hash: Hash,
    pub length: usize,
    pub content_type: String,
}

/// Builder for FileMetadata.
/// This is used to build the FileMetadata from a stream of chunks.
#[derive(Debug, Clone, Default)]
pub struct FileMetadataBuilder {
    hasher: Hasher,
    length: usize,
    path_content_type: Option<String>,
    magic_bytes_content_type: Option<String>,
}

impl FileMetadataBuilder {
    pub fn update(&mut self, chunk: &[u8]) {
        let is_first_chunk = self.length == 0;
        if is_first_chunk {
            if let Some(ctype) = infer::get(chunk) {
                self.magic_bytes_content_type = Some(ctype.mime_type().to_string());
            }
        }
        self.hasher.update(chunk);
        self.length += chunk.len();
    }

    /// If a path is provided it can be used to guess the content type.
    /// This is useful in case the magic bytes are not enough to determine the content type.
    pub fn guess_mime_type_from_path(&mut self, path: &str) {
        let content_type = mime_guess::from_path(path)
            .first_or_octet_stream()
            .to_string();
        self.path_content_type = Some(content_type);
    }

    /// Derives the content type from the magic bytes or the path.
    /// If both methods detect a type, the magic bytes method takes precedence.
    /// Defaults to application/octet-stream if no type is detected.
    fn derived_content_type(&self) -> String {
        if let Some(magic_bytes_content_type) = &self.magic_bytes_content_type {
            return magic_bytes_content_type.clone();
        }
        if let Some(path_content_type) = &self.path_content_type {
            return path_content_type.clone();
        }
        DEFAULT_CONTENT_TYPE.to_string()
    }

    pub fn finalize(self) -> FileMetadata {
        FileMetadata {
            hash: self.hasher.finalize(),
            length: self.length,
            content_type: self.derived_content_type(),
        }
    }
}

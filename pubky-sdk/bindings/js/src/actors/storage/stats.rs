use serde::{Deserialize, Serialize};
use tsify::Tsify;

/// Resource metadata returned by `SessionStorage.stats()` and `PublicStorage.stats()`.
///
/// @typedef {Object} ResourceStats
/// @property {number=} contentLength  Size in bytes.
/// @property {string=} contentType    Media type (e.g. "application/json; charset=utf-8").
/// @property {number=} lastModifiedMs Unix epoch milliseconds.
/// @property {string=} etag           Server ETag for the current version.
///
/// @example
/// const stats = await pubky.publicStorage.stats(`${user}/pub/app/file.json`);
/// if (stats) {
///   console.log(stats.contentLength, stats.contentType, stats.lastModifiedMs);
/// }
///
/// Notes:
/// - `contentLength` equals `getBytes(...).length`.
/// - `etag` may be absent. Strong tags are unquoted and can be passed to
///   `putBytesIfMatch`; weak tags retain their `W/\"...\"` wire form and cannot.
/// - `lastModifiedMs` increases when the resource is updated.
#[derive(Tsify, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceStats {
    /// Size in bytes of the stored object.
    #[tsify(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_length: Option<u64>,

    /// Media type of the stored object (e.g., `"application/json"`).
    #[tsify(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,

    /// Unix epoch **milliseconds** for the last modification time.
    #[tsify(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_modified_ms: Option<u64>,

    /// Entity tag identifying the current stored version. Strong tags are
    /// unquoted; weak tags retain their `W/\"...\"` wire form.
    #[tsify(optional)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
}

impl From<pubky::ResourceStats> for ResourceStats {
    fn from(s: pubky::ResourceStats) -> Self {
        let last_modified_ms = s.last_modified.map(|t| {
            t.duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64
        });
        Self {
            content_length: s.content_length,
            content_type: s.content_type,
            last_modified_ms,
            etag: s.etag,
        }
    }
}

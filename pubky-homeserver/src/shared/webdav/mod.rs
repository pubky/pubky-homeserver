/// Storage path types used by client and admin routes:
///
/// - `StoragePath` = Basically a regular absolute filesystem path like `/home/shacollision/test.txt`. This is used in the internal `file_service` as this should not be tied to the `/pub` requirement.
/// - `EntryPath` = A `StoragePath` that starts with a public key.
/// - `WebDavPathAxum` = A webdav path without the leading `/` because axum delivers the path param without the slash. The storage-root (`/pub/`, `/priv/`) requirement is enforced separately as an authorization concern, not by this type.
/// - `EntryPathPub` = An `EntryPath` wrapper used by admin routes.
///
/// Client storage requests use `/storage/{user_z32}/{path}`, which carries both
/// parts of an `EntryPath` in the URL. New code should use this form.
/// `WebDavPathAxum` remains necessary only for deprecated owner-relative routes,
/// where the public key is resolved through the legacy `pubky-host` mechanism.
///
/// # Storage roots
/// This needs more research especially in consideration with Cryptrees. I see a future where "permissions" are set on an individual folder level and not forced on top level folders. TBD though.
/// via: <https://github.com/pubky/pubky-homeserver/pull/145#discussion_r2149297326>
///
mod entry_path;
mod entry_path_pub;
mod webdav_path_axum;

pub use entry_path::EntryPath;
pub use entry_path_pub::EntryPathPub;
pub use pubky_common::StoragePath;
pub use webdav_path_axum::{WebDavFilePathAxum, WebDavPathAxum};

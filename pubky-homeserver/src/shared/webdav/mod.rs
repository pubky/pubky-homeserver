/// The problem we have is that we need to cover these cases of webdav paths:
///
/// - `StoragePath` = Basically a regular absolute filesystem path like `/home/shacollision/test.txt`. This is used in the internal `file_service` as this should not be tied to the `/pub` requirement.
/// - `EntryPath` = A `StoragePath` that starts with a public key.
/// - `WebDavPathAxum` = A webdav path without the leading `/` because axum delivers the path param without the slash. The storage-root (`/pub/`, `/priv/`) requirement is enforced separately as an authorization concern, not by this type.
/// - `EntryPathPub` = An `EntryPath` wrapper used by admin routes.
///
/// One reason we can't just exclusively use the `EntryPath` and need to use `WebDavPathAxum` is because sometimes, the public key comes from the `pubky-host` instead of the URL.
///
/// # How to fix it
/// ## `pubky-host`
/// We need to stop using the pubky-host hack. Instead the api should look like this:
/// `https://qtnyghnq9swketdtj9drc7rs5pfnxhs61gq4jwd317ezdegcrbco/dav/qtnyghnq9swketdtj9drc7rs5pfnxhs61gq4jwd317ezdegcrbco/pub/test.txt`
/// The public key is duplicated in this example. This way, even though the domain name changes (in the browser for example or through a redirect), the path is still valid
/// This solves the need for nginx hacks and simplifies the homeserver code.
///
/// It also allows to pick the homeserver where you want the data from.
/// For example, `userA` has his data saved on `homeserverA` and mirrored to `homeserverB`.
/// - `https://{homeserverA}/dav/{userA}/pub/test.txt`
/// - `https://{homeserverB}/dav/{userA}/pub/test.txt`
///
/// pubky-host is a terrible hack. One should not use the domain name as data.
///
/// ## Get rid of `/pub` requirement
/// This needs more research especially in consideration with Cryptrees. I see a future where "permissions" are set on an individual folder level and not forced on top level folders. TBD though.
/// via: <https://github.com/pubky/pubky-core/pull/145#discussion_r2149297326>
///
mod entry_path;
mod entry_path_pub;
mod webdav_path_axum;

pub use entry_path::EntryPath;
pub use entry_path_pub::EntryPathPub;
pub use pubky_common::StoragePath;
pub use webdav_path_axum::{WebDavFilePathAxum, WebDavPathAxum};

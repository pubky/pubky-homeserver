//! Typed addressing for files on a Pubky homeserver.
//!
//! # Why two address shapes?
//! Pubky paths come in two *disjoint* forms, each used by a different part of the API:
//!
//! - [`ResourcePath`]: an **absolute**, URL-safe path like `"/pub/my-cool-app/file"`.
//!   It contains **no user** information and is used by *session-scoped* (authenticated)
//!   operations that act “as me”. Example: `session.storage().get("/pub/my-cool-app/file")`.
//!
//! - [`PubkyResource`]: an **addressed resource** that pairs a user with an absolute path,
//!   e.g. `pubky://<public_key>/pub/my-cool-app/file`.
//!   It is used by *public* (unauthenticated) operations and any API that must
//!   target **another user’s** data. Example: `public.get("pubky://<pk>/pub/site/index.html")`.
//!
//! Keeping these distinct eliminates ambiguity and makes IDE auto-completion
//! tell you exactly what each method expects.
//!
//! We intentionally do **not** accept `https://_pubky.<pk>/...` here; higher-level
//! APIs handle resolution and URL formation for you.

use std::{fmt, str::FromStr};

use crate::PublicKey;
use percent_encoding::percent_decode_str;
use url::Url;

use crate::{Error, errors::RequestError};

#[inline]
fn invalid(msg: impl Into<String>) -> Error {
    RequestError::Validation {
        message: msg.into(),
    }
    .into()
}

// ============================================================================
// ResourcePath
// ============================================================================

/// An **absolute, URL-safe** homeserver path (`/…`), with percent-encoding where needed.
///
/// - Always normalized to start with `/`.
/// - Rejects `.` and `..` segments (no path traversal).
/// - Rejects empty **internal** segments (i.e., `//`); preserves a trailing `/`.
/// - Percent-encodes segments using `url::Url` rules (UTF-8).
///
/// Accepts both `"pub/my-cool-app/file"` and `"/pub/my-cool-app/file"` and normalizes to an
/// absolute form.
///
/// ### Examples
/// ```
/// # use pubky::ResourcePath;
/// // Parse from &str (relative becomes absolute)
/// let p = ResourcePath::parse("pub/my-cool-app/file")?;
/// assert_eq!(p.to_string(), "/pub/my-cool-app/file");
///
/// // Trailing slash is preserved
/// let dir = ResourcePath::parse("/pub/my-cool-app/")?;
/// assert_eq!(dir.to_string(), "/pub/my-cool-app/");
///
/// // Percent-encoding
/// let enc = ResourcePath::parse("pub/My File.txt")?;
/// assert_eq!(enc.to_string(), "/pub/My%20File.txt");
/// # Ok::<(), pubky::Error>(())
/// ```
///
/// ### Errors
/// Returns [`Error::Request`] (validation) on:
/// - empty input
/// - `//` within the path
/// - `.` or `..` segments
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ResourcePath(String);

impl ResourcePath {
    /// Parse, validate, and normalize to an absolute HTTP-safe path.
    ///
    /// See type docs for rules and examples.
    ///
    /// # Errors
    /// - Returns [`Error::Request`] when the input is empty, contains `.`/`..`, or has empty segments (`//`).
    /// - Returns [`Error::Request`] if internal URL handling fails while normalizing the path.
    pub fn parse<S: AsRef<str>>(s: S) -> Result<Self, Error> {
        let raw = s.as_ref();
        if raw.is_empty() {
            return Err(invalid("path cannot be empty"));
        }

        // Normalize to absolute (keep "/" as-is).
        let input = if raw.starts_with('/') {
            raw.to_string()
        } else {
            format!("/{raw}")
        };
        if input == "/" {
            return Ok(Self("/".to_string()));
        }
        let wants_trailing = input.ends_with('/');

        // Build via URL path segments (handles percent-encoding).
        let mut u = Url::parse("dummy:///").map_err(|_err| invalid("internal URL setup failed"))?;
        {
            let mut segs = u
                .path_segments_mut()
                .map_err(|_err| invalid("internal URL path handling failed"))?;
            segs.clear();

            let mut parts = input.trim_start_matches('/').split('/').peekable();
            while let Some(seg) = parts.next() {
                if seg.is_empty() {
                    // Only allow the final empty segment (trailing slash)
                    if parts.peek().is_none() && wants_trailing {
                        break;
                    }
                    return Err(invalid("path contains empty segment ('//')"));
                }
                if seg == "." || seg == ".." {
                    return Err(invalid("path cannot contain '.' or '..'"));
                }
                segs.push(seg);
            }
            if wants_trailing {
                segs.push(""); // encode trailing slash
            }
        }

        Ok(Self(u.path().to_string()))
    }

    /// Borrow the normalized absolute path as `&str`.
    #[inline]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[inline]
    fn as_root_relative_str(&self) -> &str {
        self.as_str().trim_start_matches('/')
    }
}

impl FromStr for ResourcePath {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for ResourcePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ============================================================================
// PubkyResource
// ============================================================================

/// An **addressed resource**: `(owner: PublicKey, path: ResourcePath)`.
///
/// This is the unambiguous “user + absolute path” form used when acting on
/// **another user’s** data (public reads, etc.).
///
/// Canonically renders as `pubky://<public_key>/<abs-path>`.
///
/// Legacy `pubky<public_key>/<abs-path>` values remain accepted as input for compatibility.
///
/// ### Examples
/// ```
/// # use pubky::Keypair;
/// # use pubky::{PubkyResource, ResourcePath};
/// // Build from parts
/// let pk = Keypair::random().public_key();
/// let r = PubkyResource::new(pk.clone(), "/pub/site/index.html")?;
/// assert_eq!(r.to_string(), format!("pubky://{pk}/pub/site/index.html"));
///
/// // Parse from string
/// // `pubky://` form
/// let parsed2: PubkyResource = format!("pubky://{}/pub/site/index.html", pk.z32()).parse()?;
///
/// # Ok::<(), pubky::Error>(())
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PubkyResource {
    /// The resource owner’s public key.
    pub owner: PublicKey,
    /// The owner-relative, normalized absolute path.
    pub path: ResourcePath,
}

impl PubkyResource {
    /// Construct from `owner` and a path-like value (normalized to [`ResourcePath`]).
    ///
    /// # Errors
    /// - Returns [`Error::Request`] if the provided path cannot be normalized into an absolute [`ResourcePath`].
    pub fn new<S: AsRef<str>>(owner: PublicKey, path: S) -> Result<Self, Error> {
        Ok(Self {
            owner,
            path: ResourcePath::parse(path)?,
        })
    }

    /// Render as `pubky://<owner>/<abs-path>` (deep-link form).
    ///
    /// Useful when storing or sharing canonical identifiers that include the
    /// owner’s public key. The returned string never contains a leading
    /// double-slash in the path (`pubky://<pk>//...`) because [`ResourcePath`]
    /// is always normalized.
    #[must_use]
    pub fn to_pubky_url(&self) -> String {
        let path = self.path.as_root_relative_str();
        format!("pubky://{}/{path}", self.owner.z32())
    }

    /// Render as the canonical path-addressed transport URL:
    /// `https://_pubky.<owner>/storage/<owner>/<abs-path>`.
    ///
    /// It is the same mapping performed by [`resolve_pubky`].
    ///
    /// # Errors
    /// - Returns [`Error::Request`] if the constructed transport URL is invalid.
    pub fn to_transport_url(&self) -> Result<Url, Error> {
        let owner = self.owner.z32();
        let path = self.path.as_root_relative_str();
        let https = format!("https://_pubky.{owner}/storage/{owner}/{path}");
        Ok(Url::parse(&https)?)
    }

    /// Parse canonical `/storage/<owner>/...` and legacy `_pubky.<owner>/...` URLs.
    /// Canonical URLs take the owner from the path; legacy URLs use the host.
    ///
    /// # Errors
    /// Returns [`Error::Request`] when the owner or path is malformed.
    pub fn from_transport_url(url: &Url) -> Result<Self, Error> {
        let (owner, path) = if let Some(path) = url.path().strip_prefix("/storage/") {
            let (owner, path) = path
                .split_once('/')
                .ok_or_else(|| invalid("storage transport URL is missing a resource path"))?;
            let owner = parse_transport_owner(owner)?;

            if let Some(host_owner) = url.host_str().and_then(|host| host.strip_prefix("_pubky."))
                && parse_transport_owner(host_owner)? != owner
            {
                return Err(invalid(
                    "storage transport URL owner does not match its `_pubky` host",
                ));
            }

            (owner, path)
        } else {
            let owner = url
                .host_str()
                .and_then(|host| host.strip_prefix("_pubky."))
                .ok_or_else(|| invalid("legacy transport URL is missing a `_pubky` host"))?;
            (parse_transport_owner(owner)?, url.path())
        };

        let path = if path.is_empty() { "/" } else { path };
        let decoded_path = percent_decode_str(path)
            .decode_utf8()
            .map_err(|_err| invalid("transport URL path is not valid UTF-8"))?;
        Self::new(owner, decoded_path.as_ref())
    }
}

fn parse_transport_owner(owner: &str) -> Result<PublicKey, Error> {
    if PublicKey::is_pubky_prefixed(owner) {
        return Err(invalid(
            "transport URL owner must use raw z32 without `pubky` prefix",
        ));
    }

    PublicKey::try_from_z32(owner)
        .map_err(|_err| invalid("transport URL contains an invalid owner"))
}

impl FromStr for PubkyResource {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // 1) pubky://<user>/<path>
        if let Some(rest) = s.strip_prefix("pubky://") {
            let (user_str, path) = rest
                .split_once('/')
                .ok_or_else(|| invalid("missing `<user>/<path>`"))?;
            if PublicKey::is_pubky_prefixed(user_str) {
                return Err(invalid(
                    "unexpected `pubky` prefix in user id; use raw z32 after `pubky://`",
                ));
            }
            let user = PublicKey::try_from_z32(user_str)
                .map_err(|_err| invalid(format!("invalid user public key: {user_str}")))?;
            return Self::new(user, path);
        }

        // 2) Legacy pubky<user>/<path>
        if let Some(rest) = s.strip_prefix("pubky") {
            if let Some((user_id, path)) = rest.split_once('/') {
                if PublicKey::is_pubky_prefixed(user_id) {
                    return Err(invalid(
                        "unexpected `pubky` prefix in user id; use raw z32 after `pubky`",
                    ));
                }
                let user = PublicKey::try_from_z32(user_id).map_err(|_err| {
                    invalid("expected `pubky<user>/<path>` or `pubky://<user>/<path>`")
                })?;
                return Self::new(user, path);
            }
            return Err(invalid(
                "expected `pubky<user>/<path>` or `pubky://<user>/<path>`",
            ));
        }

        Err(invalid(
            "expected `pubky<user>/<path>` or `pubky://<user>/<path>`",
        ))
    }
}

impl fmt::Display for PubkyResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_pubky_url())
    }
}

/// Resolve a Pubky URL into a transport URL.
///
/// Legacy `pubky<pk>/…` identifiers remain accepted for compatibility.
///
/// Returns the same URL as [`PubkyResource::to_transport_url`], making it easy to
/// bridge human-facing identifiers with low-level HTTP clients.
///
/// # Errors
/// - Returns [`Error::Request`] if the identifier cannot be parsed into a [`PubkyResource`].
/// - Propagates errors from [`PubkyResource::to_transport_url`] when building the transport URL.
pub fn resolve_pubky<S: AsRef<str>>(input: S) -> Result<Url, Error> {
    let resource: PubkyResource = input.as_ref().parse()?;
    resource.to_transport_url()
}

// ============================================================================
// Conversion traits
// ============================================================================

/// Convert common input types into a normalized [`ResourcePath`] (absolute).
///
/// This trait is intentionally implemented for the “obvious” path-like things:
/// - `ResourcePath` / `&ResourcePath` (pass-through / clone)
/// - `&str`, `String`, and `&String`
///
/// It is used by *session-scoped* storage methods (`SessionStorage`) that act as
/// the current user and therefore do **not** need a `PublicKey`.
///
/// ### Examples
/// ```
/// # use pubky::{IntoResourcePath, ResourcePath};
/// fn takes_abs<P: IntoResourcePath>(p: P) -> pubky::Result<ResourcePath> {
///     p.into_abs_path()
/// }
///
/// let a = takes_abs("/pub/my-cool-app/file")?;
/// let b = takes_abs("pub/my-cool-app/file")?;
/// assert_eq!(a, b);
/// # Ok::<(), pubky::Error>(())
/// ```
pub trait IntoResourcePath {
    /// Convert into a validated, normalized absolute [`ResourcePath`].
    ///
    /// # Errors
    /// - Returns [`Error::Request`] if the input cannot be normalized into a valid absolute path.
    fn into_abs_path(self) -> Result<ResourcePath, Error>;
}

impl IntoResourcePath for ResourcePath {
    #[inline]
    fn into_abs_path(self) -> Result<ResourcePath, Error> {
        Ok(self)
    }
}
impl IntoResourcePath for &ResourcePath {
    #[inline]
    fn into_abs_path(self) -> Result<ResourcePath, Error> {
        Ok(self.clone())
    }
}
impl IntoResourcePath for &str {
    fn into_abs_path(self) -> Result<ResourcePath, Error> {
        ResourcePath::from_str(self)
    }
}
impl IntoResourcePath for String {
    fn into_abs_path(self) -> Result<ResourcePath, Error> {
        ResourcePath::from_str(&self)
    }
}
impl IntoResourcePath for &String {
    fn into_abs_path(self) -> Result<ResourcePath, Error> {
        ResourcePath::from_str(self.as_str())
    }
}

/// Convert common input types into a normalized, **addressed** [`PubkyResource`].
///
/// Implementations:
/// - `PubkyResource` / `&PubkyResource` (pass-through / clone)
/// - `&str`, `String`, `&String` parsed as `pubky://<pk>/<abs-path>`
/// - `(PublicKey, P: AsRef<str>)` and `(&PublicKey, P: AsRef<str>)` to pair a key with a path
///
/// This trait is used by *public* storage methods (`PublicStorage`) and any API that must
/// reference **another user’s** data explicitly.
///
/// ### Examples
/// ```
/// # use pubky::Keypair;
/// # use pubky::{IntoPubkyResource, PubkyResource};
/// let user = Keypair::random().public_key();
///
/// // Pair (pk, path)
/// let r1 = (user.clone(), "/pub/site/index.html").into_pubky_resource()?;
///
/// // Parse `pubky://`
/// let r2: PubkyResource = format!("pubky://{user}/pub/site/index.html").parse()?;
/// # Ok::<(), pubky::Error>(())
/// ```
pub trait IntoPubkyResource {
    /// Convert into a validated, normalized [`PubkyResource`].
    ///
    /// # Errors
    /// - Returns [`Error::Request`] if the input cannot be parsed into an addressed resource.
    fn into_pubky_resource(self) -> Result<PubkyResource, Error>;
}

impl IntoPubkyResource for PubkyResource {
    #[inline]
    fn into_pubky_resource(self) -> Result<PubkyResource, Error> {
        Ok(self)
    }
}
impl IntoPubkyResource for &PubkyResource {
    #[inline]
    fn into_pubky_resource(self) -> Result<PubkyResource, Error> {
        Ok(self.clone())
    }
}
impl IntoPubkyResource for &str {
    fn into_pubky_resource(self) -> Result<PubkyResource, Error> {
        PubkyResource::from_str(self)
    }
}
impl IntoPubkyResource for String {
    fn into_pubky_resource(self) -> Result<PubkyResource, Error> {
        PubkyResource::from_str(&self)
    }
}
impl IntoPubkyResource for &String {
    fn into_pubky_resource(self) -> Result<PubkyResource, Error> {
        PubkyResource::from_str(self.as_str())
    }
}
impl<P: AsRef<str>> IntoPubkyResource for (PublicKey, P) {
    fn into_pubky_resource(self) -> Result<PubkyResource, Error> {
        PubkyResource::new(self.0, self.1.as_ref())
    }
}
impl<P: AsRef<str>> IntoPubkyResource for (&PublicKey, P) {
    fn into_pubky_resource(self) -> Result<PubkyResource, Error> {
        PubkyResource::new(self.0.clone(), self.1.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keypair;

    #[test]
    fn file_path_normalization_and_rejections() {
        // Normalize relative
        assert_eq!(
            ResourcePath::parse("pub/my.app").unwrap().as_str(),
            "/pub/my.app"
        );
        // Keep absolute
        assert_eq!(
            ResourcePath::parse("/pub/my.app").unwrap().as_str(),
            "/pub/my.app"
        );
        // Reject empty
        assert!(matches!(
            ResourcePath::parse(""),
            Err(Error::Request(RequestError::Validation { .. }))
        ));
        // Reject double-slash
        assert!(matches!(
            ResourcePath::parse("/pub//app"),
            Err(Error::Request(RequestError::Validation { .. }))
        ));
    }

    #[test]
    fn parses_legacy_identifier_but_renders_a_pubky_url() {
        let kp = Keypair::random();
        let user = kp.public_key();
        let user_raw = user.z32();
        let s1 = format!("pubky://{user_raw}/pub/my-cool-app/file");
        let s3 = format!("pubky{user_raw}/pub/my-cool-app/file");

        let p1 = PubkyResource::from_str(&s1).unwrap();
        let p3 = PubkyResource::from_str(&s3).unwrap();

        assert_eq!(p1.owner, user);
        assert_eq!(p3.owner, user);
        assert_eq!(p1.path.as_str(), "/pub/my-cool-app/file");
        assert_eq!(p3.path.as_str(), "/pub/my-cool-app/file");

        assert_eq!(p1.to_string(), s1);
        assert_eq!(p3.to_string(), s1);
        assert_eq!(p1.to_pubky_url(), s1);
    }

    #[test]
    fn session_scoped_paths_and_rendering() {
        // Session-scoped absolute path is represented by ResourcePath
        let p_abs = ResourcePath::parse("/pub/my-cool-app/file").unwrap();
        assert_eq!(p_abs.as_str(), "/pub/my-cool-app/file");

        // PubkyResource::from_str("/...") must fail (owner is required)
        assert!(matches!(
            PubkyResource::from_str("/pub/my-cool-app/file"),
            Err(Error::Request(RequestError::Validation { .. }))
        ));

        // To render a pubky:// URL, pair with an explicit owner
        let kp = Keypair::random();
        let user = kp.public_key();
        let r = PubkyResource::new(user.clone(), p_abs.as_str()).unwrap();
        assert_eq!(
            r.to_pubky_url(),
            format!("pubky://{}/pub/my-cool-app/file", user.z32())
        );
    }

    #[test]
    fn error_cases() {
        let kp = Keypair::random();
        let user = kp.public_key();

        // Invalid user key in identifier
        assert!(matches!(
            PubkyResource::from_str("pubkynot-a-key/pub/my.app"),
            Err(Error::Request(RequestError::Validation { .. }))
        ));

        // Double-slash inside path
        let s_bad = format!("pubky://{user}/pub//app");
        assert!(matches!(
            PubkyResource::from_str(&s_bad),
            Err(Error::Request(RequestError::Validation { .. }))
        ));
    }

    #[test]
    fn percent_encoding_and_unicode() {
        assert_eq!(
            ResourcePath::parse("pub/My File.txt").unwrap().as_str(),
            "/pub/My%20File.txt"
        );
        assert_eq!(
            ResourcePath::parse("/ä/β/漢").unwrap().as_str(),
            "/%C3%A4/%CE%B2/%E6%BC%A2"
        );
    }

    #[test]
    fn rejects_dot_segments_but_allows_trailing_slash() {
        ResourcePath::parse("/a/./b").unwrap_err();
        ResourcePath::parse("/a/../b").unwrap_err();
        assert_eq!(
            ResourcePath::parse("/pub/my-cool-app/").unwrap().as_str(),
            "/pub/my-cool-app/"
        );
    }

    #[test]
    fn resolve_identifiers() {
        let kp = Keypair::random();
        let user = kp.public_key();
        let user_raw = user.z32();
        let base = format!("pubky://{}/pub/site/index.html", user.z32());
        let resolved = resolve_pubky(&base).unwrap();
        assert_eq!(
            resolved.as_str(),
            format!("https://_pubky.{user_raw}/storage/{user_raw}/pub/site/index.html")
        );

        let prefixed = format!("pubky{}/pub/site/index.html", user.z32());
        let resolved2 = resolve_pubky(&prefixed).unwrap();
        assert_eq!(resolved, resolved2);

        let resource = PubkyResource::from_str(&prefixed).unwrap();
        assert_eq!(resource.to_string(), base);
        assert_eq!(resource.to_transport_url().unwrap(), resolved);

        let parsed = PubkyResource::from_transport_url(&resolved).unwrap();
        assert_eq!(parsed, resource);

        let homeserver = Keypair::random().public_key();
        let explicit_homeserver = Url::parse(&format!(
            "https://{}/storage/{user_raw}/pub/site/index.html",
            homeserver.z32()
        ))
        .unwrap();
        assert_eq!(
            PubkyResource::from_transport_url(&explicit_homeserver).unwrap(),
            resource
        );

        let legacy = Url::parse(&format!("https://_pubky.{user_raw}/pub/site/index.html")).unwrap();
        assert_eq!(
            PubkyResource::from_transport_url(&legacy).unwrap(),
            resource
        );

        let http_url =
            Url::parse(&format!("http://_pubky.{}/pub/site/index.html", user.z32())).unwrap();
        let parsed_http = PubkyResource::from_transport_url(&http_url).unwrap();
        assert_eq!(parsed_http, resource);
    }

    #[test]
    fn canonical_transport_rejects_a_conflicting_pubky_host() {
        let host_owner = Keypair::random().public_key();
        let path_owner = Keypair::random().public_key();
        let url = Url::parse(&format!(
            "https://_pubky.{}/storage/{}/pub/My%20File.txt",
            host_owner.z32(),
            path_owner.z32()
        ))
        .unwrap();

        let error = PubkyResource::from_transport_url(&url).unwrap_err();
        assert!(error.to_string().contains("does not match"));
    }

    #[test]
    fn canonical_transport_accepts_an_icann_homeserver_authority() {
        let owner = Keypair::random().public_key();
        let url = Url::parse(&format!(
            "https://example.com/storage/{}/pub/My%20File.txt",
            owner.z32()
        ))
        .unwrap();

        let resource = PubkyResource::from_transport_url(&url).unwrap();
        assert_eq!(resource.owner, owner);
        assert_eq!(resource.path.as_str(), "/pub/My%20File.txt");
    }

    #[test]
    fn transport_owner_rejects_the_pubky_prefix() {
        let owner = Keypair::random().public_key();
        let url = Url::parse(&format!(
            "https://example.com/storage/pubky{}/pub/file.txt",
            owner.z32()
        ))
        .unwrap();

        let error = PubkyResource::from_transport_url(&url).unwrap_err();
        assert!(error.to_string().contains("must use raw z32"));
    }
}

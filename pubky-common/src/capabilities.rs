//! Capabilities define *what* a bearer can access (a scoped path) and *how* (a set of actions).
//!
//! ## String format
//!
//! A single capability is serialized as: `"<scope>:<actions>"`
//!
//! - `scope` must start with `/` (e.g. `"/pub/my-cool-app/"`, `"/"`).
//! - `actions` contains at least one action letter, currently:
//!   - `r` => read (GET)
//!   - `w` => write (PUT/POST/DELETE)
//!
//! Examples:
//!
//! - Read+write everything: `"/:rw"`
//! - Read-only a file: `"/pub/foo.txt:r"`
//! - Read-write a directory: `"/pub/my-cool-app/:rw"`
//!
//! Multiple capabilities are serialized as a comma-separated list,
//! e.g. `"/pub/my-cool-app/:rw,/pub/foo.txt:r"`.
//!
//! ## Construction
//!
//! ```rust
//! use pubky_common::capabilities::{Capability, Capabilities};
//!
//! let cap = Capability::read_write("/pub/my-cool-app/").unwrap();
//! assert_eq!(cap.to_string(), "/pub/my-cool-app/:rw");
//!
//! // Multiple caps builder
//! let caps = Capabilities::builder()
//!     .read_write("/pub/my-cool-app/")
//!     .unwrap()
//!     .read("/pub/foo.txt")
//!     .unwrap()
//!     .finish();
//! assert_eq!(caps.to_string(), "/pub/my-cool-app/:rw,/pub/foo.txt:r");
//! ```

use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt::Display, str::FromStr};
use url::Url;

use crate::{StoragePath, StoragePathError};

/// A single capability: a `scope` and the allowed `actions` within it.
///
/// The wire/string representation is `"<scope>:<actions>"`, see module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    /// Canonical scope of resources, such as a directory or file.
    scope: StoragePath,
    /// Allowed actions within `scope`. Serialized as a compact action string (e.g. `"rw"`).
    actions: Vec<Action>,
}

impl Capability {
    /// Shorthand for a root capability at `/` with read+write.
    ///
    /// Equivalent to a capability with scope `/` and both read and write actions.
    ///
    /// ```
    /// use pubky_common::capabilities::Capability;
    /// assert_eq!(Capability::root().to_string(), "/:rw");
    /// ```
    pub fn root() -> Self {
        Capability {
            scope: StoragePath::new("/").expect("root is a canonical path"),
            actions: vec![Action::Read, Action::Write],
        }
    }

    // ---- Shortcut constructors

    /// Construct a read-only capability for `scope`.
    ///
    /// ```
    /// use pubky_common::capabilities::Capability;
    /// assert_eq!(Capability::read("/pub/my.app").unwrap().to_string(), "/pub/my.app:r");
    /// ```
    #[inline]
    pub fn read(scope: impl AsRef<str>) -> Result<Self, CapabilityParseError> {
        Self::with_actions(scope.as_ref(), vec![Action::Read])
    }

    /// Construct a write-only capability for `scope`.
    ///
    /// ```
    /// use pubky_common::capabilities::Capability;
    /// assert_eq!(Capability::write("/pub/tmp").unwrap().to_string(), "/pub/tmp:w");
    /// ```
    #[inline]
    pub fn write(scope: impl AsRef<str>) -> Result<Self, CapabilityParseError> {
        Self::with_actions(scope.as_ref(), vec![Action::Write])
    }

    /// Construct a read+write capability for `scope`.
    ///
    /// ```
    /// use pubky_common::capabilities::Capability;
    /// assert_eq!(Capability::read_write("/").unwrap().to_string(), "/:rw");
    /// ```
    #[inline]
    pub fn read_write(scope: impl AsRef<str>) -> Result<Self, CapabilityParseError> {
        Self::with_actions(scope.as_ref(), vec![Action::Read, Action::Write])
    }

    fn with_actions(scope: &str, actions: Vec<Action>) -> Result<Self, CapabilityParseError> {
        Ok(Self {
            scope: parse_scope(scope)?,
            actions,
        })
    }

    /// Return the resource scope covered by this capability.
    pub fn scope(&self) -> &StoragePath {
        &self.scope
    }

    /// Return the actions allowed by this capability.
    pub fn actions(&self) -> &[Action] {
        &self.actions
    }

    /// Whether this is the root capability (`/:rw`).
    pub fn is_root(&self) -> bool {
        *self == Self::root()
    }

    /// Whether this capability's scope covers the given path.
    ///
    /// The trailing `/` on a scope is significant — it distinguishes a
    /// *directory* scope from a *file* scope:
    ///
    /// - **Directory scope** (ends in `/`): covers the directory itself and
    ///   any path inside it. `/pub/app/` covers `/pub/app/`, `/pub/app/foo`,
    ///   and `/pub/app/sub/bar`, but NOT `/pub/app` or `/pub/app-evil/foo`.
    /// - **File scope** (no trailing `/`): covers only the exact path.
    ///   `/pub/app` covers `/pub/app` and nothing else — not `/pub/app/foo`
    ///   (that's inside the *directory* `/pub/app/`, a different resource)
    ///   and not `/pub/app-evil` (no prefix-as-string matching).
    pub fn scope_covers_path(&self, path: &StoragePath) -> bool {
        if self.scope == *path {
            return true;
        }
        // Only directory scopes (trailing `/`) cover descendant paths.
        // For a file scope, only exact-match (handled above) is allowed.
        self.scope.is_directory() && path.as_str().starts_with(self.scope.as_str())
    }

    /// Whether this capability fully covers `other` — i.e. the scope is equal or
    /// broader, and every action (read/write) in `other` is also present in `self`.
    fn covers(&self, other: &Capability) -> bool {
        if !self.scope_covers_path(other.scope()) {
            return false;
        }

        other
            .actions
            .iter()
            .all(|action| self.actions.contains(action))
    }
}

/// Actions allowed on a given scope.
///
/// Display/serialization encodes these as single characters (`r`, `w`).
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    /// Can read the scope at the specified path (GET requests).
    Read,
    /// Can write to the scope at the specified path (PUT/POST/DELETE requests).
    Write,
    /// Unknown ability
    Unknown(char),
}

impl From<&Action> for char {
    fn from(value: &Action) -> Self {
        match value {
            Action::Read => 'r',
            Action::Write => 'w',
            Action::Unknown(char) => char.to_owned(),
        }
    }
}

impl TryFrom<char> for Action {
    type Error = CapabilityParseError;

    fn try_from(value: char) -> Result<Self, Self::Error> {
        match value {
            'r' => Ok(Self::Read),
            'w' => Ok(Self::Write),
            _ => Err(CapabilityParseError::InvalidAction(value)),
        }
    }
}

impl Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}",
            self.scope,
            self.actions.iter().map(char::from).collect::<String>()
        )
    }
}

impl TryFrom<String> for Capability {
    type Error = CapabilityParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl FromStr for Capability {
    type Err = CapabilityParseError;

    /// Parse `"<scope>:<actions>"`.
    ///
    /// ```
    /// use pubky_common::capabilities::Capability;
    /// let capability: Capability = "/pub/my-cool-app/:rw".parse().unwrap();
    /// assert_eq!(capability.to_string(), "/pub/my-cool-app/:rw");
    /// ```
    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (scope, actions_str) = value
            .split_once(':')
            .ok_or(CapabilityParseError::InvalidFormat)?;

        if actions_str.contains(':') {
            return Err(CapabilityParseError::InvalidFormat);
        }

        if actions_str.is_empty() {
            return Err(CapabilityParseError::MissingActions);
        }

        let mut actions = Vec::new();

        for character in actions_str.chars() {
            let action = Action::try_from(character)?;

            if let Err(index) = actions.binary_search(&action) {
                actions.insert(index, action);
            }
        }

        Ok(Self {
            scope: parse_scope(scope)?,
            actions,
        })
    }
}

impl TryFrom<&str> for Capability {
    type Error = CapabilityParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl Serialize for Capability {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let string = self.to_string();

        string.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Capability {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let string: String = Deserialize::deserialize(deserializer)?;

        string.parse().map_err(serde::de::Error::custom)
    }
}

/// Error parsing a [Capability].
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum CapabilityParseError {
    /// The scope is not a canonical WebDAV path.
    #[error("invalid capability scope: {0}")]
    InvalidScope(#[source] StoragePathError),
    /// The scope contains a capability wire-format delimiter.
    #[error("capability scope contains reserved delimiter `{0}`")]
    InvalidScopeDelimiter(char),
    /// The capability does not follow the `<scope>:<actions>` format.
    #[error("capability must have format `<scope>:<actions>`")]
    InvalidFormat,
    /// No actions were provided.
    #[error("capability must contain at least one action")]
    MissingActions,
    /// The action is not supported.
    #[error("invalid capability action `{0}`")]
    InvalidAction(char),
}

/// Backwards-compatible name for [`CapabilityParseError`].
pub type Error = CapabilityParseError;

/// Error parsing a comma-separated [`Capabilities`] list.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
#[error("invalid capability at position {position} (`{entry}`): {source}")]
pub struct CapabilitiesParseError {
    /// One-based position of the invalid entry.
    pub position: usize,
    /// The exact invalid entry.
    pub entry: String,
    /// The reason the entry is invalid.
    #[source]
    pub source: CapabilityParseError,
}

/// A wrapper around `Vec<Capability>` that controls how capabilities are
/// serialized and built.
///
/// Serialization is a single comma-separated string (e.g. `"/:rw,/pub/my-cool-app/:r"`),
/// which is convenient for logs, URLs, or compact text payloads. It also comes
/// with a fluent builder (`Capabilities::builder()`).
///
/// Note: this does **not** remove length prefixes in binary encodings; if you
/// need a varint-free trailing field in a custom binary format, implement a
/// bespoke encoder/decoder instead of serde.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
#[must_use]
pub struct Capabilities(Vec<Capability>);

impl Capabilities {
    /// Return a normalized capability list.
    ///
    /// Normalization merges duplicate scopes, de-duplicates and sorts actions,
    /// and removes capabilities already covered by broader capabilities.
    ///
    /// # Examples
    /// ```
    /// use pubky_common::capabilities::{Capability, Capabilities};
    ///
    /// let caps = Capabilities::from(vec![
    ///     Capability::read("/pub/").unwrap(),
    ///     Capability::write("/pub/").unwrap(),
    ///     Capability::read("/pub/file.txt").unwrap(),
    /// ]);
    ///
    /// assert_eq!(caps.normalize().to_string(), "/pub/:rw");
    /// ```
    pub fn normalize(self) -> Self {
        Self(normalize(self.0))
    }

    /// Returns true if the list contains `capability`.
    pub fn contains(&self, capability: &Capability) -> bool {
        self.0.contains(capability)
    }

    /// Returns `true` if the list is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the number of entries.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns an iterator over the slice of [Capability].
    pub fn iter(&self) -> std::slice::Iter<'_, Capability> {
        self.0.iter()
    }

    /// Start a fluent builder for multiple capabilities.
    ///
    /// ```
    /// use pubky_common::capabilities::Capabilities;
    /// let caps = Capabilities::builder().read_write("/").unwrap().finish();
    /// assert_eq!(caps.to_string(), "/:rw");
    /// ```
    pub fn builder() -> CapsBuilder {
        CapsBuilder::default()
    }

    /// Parse capabilities from the `caps` query parameter of `url`.
    ///
    /// Expects a comma-separated list of capability strings, e.g.:
    /// `?caps=/pub/my-cool-app/:rw,/foo:r`
    ///
    /// # Examples
    /// ```
    /// # use url::Url;
    /// # use pubky_common::capabilities::Capabilities;
    /// let url = Url::parse("https://example/app?caps=/pub/my-cool-app/:rw,/foo:r").unwrap();
    /// let caps = Capabilities::try_from_caps_url(&url).unwrap();
    /// assert!(!caps.is_empty());
    /// ```
    pub fn try_from_caps_url(url: &Url) -> Result<Self, CapabilitiesParseError> {
        let value = url
            .query_pairs()
            .find_map(|(k, v)| (k == "caps").then(|| v.to_string()))
            .unwrap_or_default();

        value.parse()
    }

    /// Borrow the inner capabilities as a slice without allocating.
    ///
    /// Constant-time; returns a view into the existing buffer.
    ///
    /// # Examples
    /// ```
    /// use pubky_common::capabilities::{Capability, Capabilities};
    ///
    /// let caps = Capabilities::from(vec![
    ///     Capability::read("/foo").unwrap(),
    ///     Capability::write("/bar/").unwrap(),
    /// ]);
    /// let slice: &[Capability] = caps.as_slice();
    /// assert_eq!(slice.len(), 2);
    /// ```
    #[inline]
    pub fn as_slice(&self) -> &[Capability] {
        &self.0
    }

    /// Clone the inner capability list.
    pub fn to_vec(&self) -> Vec<Capability> {
        self.0.clone()
    }
}

/// Fluent builder for multiple [`Capability`] entries.
///
/// Build with high-level helpers (`.read()/.write()/.read_write()`), or push prebuilt
/// capabilities with `.cap()`.
#[derive(Default, Debug)]
pub struct CapsBuilder {
    caps: Vec<Capability>,
}

impl CapsBuilder {
    /// Create a new empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Push a prebuilt capability
    pub fn cap(mut self, cap: Capability) -> Self {
        self.caps.push(cap);
        self
    }

    /// Add a read-only capability for `scope`.
    pub fn read(mut self, scope: impl AsRef<str>) -> Result<Self, CapabilityParseError> {
        self.caps.push(Capability::read(scope)?);
        Ok(self)
    }

    /// Add a write-only capability for `scope`.
    pub fn write(mut self, scope: impl AsRef<str>) -> Result<Self, CapabilityParseError> {
        self.caps.push(Capability::write(scope)?);
        Ok(self)
    }

    /// Add a read+write capability for `scope`.
    pub fn read_write(mut self, scope: impl AsRef<str>) -> Result<Self, CapabilityParseError> {
        self.caps.push(Capability::read_write(scope)?);
        Ok(self)
    }

    /// Extend with an iterator of capabilities.
    pub fn extend<I: IntoIterator<Item = Capability>>(mut self, iter: I) -> Self {
        self.caps.extend(iter);
        self
    }

    /// Finalize and produce the normalized [`Capabilities`] list.
    pub fn finish(self) -> Capabilities {
        Capabilities::from(self.caps).normalize()
    }
}

impl From<Vec<Capability>> for Capabilities {
    fn from(value: Vec<Capability>) -> Self {
        Self(value)
    }
}

impl From<Capabilities> for Vec<Capability> {
    fn from(value: Capabilities) -> Self {
        value.0
    }
}

impl TryFrom<&str> for Capabilities {
    type Error = CapabilitiesParseError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl FromStr for Capabilities {
    type Err = CapabilitiesParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.is_empty() {
            return Ok(Self::default());
        }

        value
            .split(',')
            .enumerate()
            .map(|(index, entry)| {
                entry.parse().map_err(|source| CapabilitiesParseError {
                    position: index + 1,
                    entry: entry.to_string(),
                    source,
                })
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Self::from)
    }
}

impl Display for Capabilities {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = self
            .0
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .join(",");

        write!(f, "{string}")
    }
}

impl Serialize for Capabilities {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_string().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Capabilities {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let string: String = Deserialize::deserialize(deserializer)?;

        string.parse().map_err(serde::de::Error::custom)
    }
}

// --- helpers ---

fn parse_scope(scope: &str) -> Result<StoragePath, CapabilityParseError> {
    for delimiter in [':', ','] {
        if scope.contains(delimiter) {
            return Err(CapabilityParseError::InvalidScopeDelimiter(delimiter));
        }
    }

    StoragePath::new(scope).map_err(CapabilityParseError::InvalidScope)
}

fn normalize(caps: Vec<Capability>) -> Vec<Capability> {
    let mut merged: Vec<Capability> = Vec::new();

    for mut cap in caps {
        if let Some(existing) = merged
            .iter_mut()
            .find(|existing| existing.scope == cap.scope)
        {
            let actions: BTreeSet<Action> = existing
                .actions
                .iter()
                .copied()
                .chain(cap.actions.iter().copied())
                .collect();
            existing.actions = actions.into_iter().collect();
            continue;
        }

        let actions: BTreeSet<Action> = cap.actions.iter().copied().collect();
        cap.actions = actions.into_iter().collect();
        merged.push(cap);
    }

    let mut sanitized: Vec<Capability> = Vec::new();

    'outer: for cap in merged.into_iter() {
        if sanitized.iter().any(|existing| existing.covers(&cap)) {
            continue 'outer;
        }

        sanitized.retain(|existing| !cap.covers(existing));
        sanitized.push(cap);
    }

    sanitized
}

#[cfg(test)]
mod tests {
    use super::*;
    use url::Url;

    #[test]
    fn root_capability_helper() {
        let cap = Capability::root();
        assert_eq!(cap.scope().as_str(), "/");
        assert_eq!(cap.actions, vec![Action::Read, Action::Write]);
        assert_eq!(cap.to_string(), "/:rw");
        // And it round-trips through the string form:
        assert_eq!("/:rw".parse(), Ok(cap));
    }

    #[test]
    fn single_capability_constructors() {
        let cap_rw = Capability::read_write("/pub/my-cool-app/").unwrap();
        let cap_r = Capability::read("/pub/file.txt").unwrap();
        let cap_w = Capability::write("/pub/uploads/").unwrap();

        assert_eq!(cap_rw.to_string(), "/pub/my-cool-app/:rw");
        assert_eq!(cap_r.to_string(), "/pub/file.txt:r");
        assert_eq!(cap_w.to_string(), "/pub/uploads/:w");
    }

    #[test]
    fn multiple_caps_with_capsbuilder() {
        let caps = Capabilities::builder()
            .read("/pub/my-cool-app/") // "/pub/my-cool-app/:r"
            .unwrap()
            .write("/pub/uploads/") // "/pub/uploads/:w"
            .unwrap()
            .read_write("/pub/my-cool-app/data/") // "/pub/my-cool-app/data/:rw"
            .unwrap()
            .finish();

        // String form is comma-separated, in insertion order:
        assert_eq!(
            caps.to_string(),
            "/pub/my-cool-app/:r,/pub/uploads/:w,/pub/my-cool-app/data/:rw"
        );

        // Contains checks:
        assert!(caps.contains(&Capability::read("/pub/my-cool-app/").unwrap()));
        assert!(caps.contains(&Capability::write("/pub/uploads/").unwrap()));
        assert!(caps.contains(&Capability::read_write("/pub/my-cool-app/data/").unwrap()));
        assert!(!caps.contains(&Capability::write("/nope").unwrap()));
    }

    #[test]
    fn action_dedup_and_order_are_stable() {
        let cap = "/:wrrw".parse::<Capability>().unwrap();
        assert_eq!(cap.actions(), &[Action::Read, Action::Write]);
        assert_eq!(cap.to_string(), "/:rw");
    }

    #[test]
    fn constructor_wraps_storage_path_errors() {
        assert_eq!(
            Capability::read("/pub//my.app").unwrap_err(),
            CapabilityParseError::InvalidScope(StoragePathError::EmptySegment)
        );
        assert_eq!(
            Capability::read("/priv/report ").unwrap_err(),
            CapabilityParseError::InvalidScope(StoragePathError::TrailingWhitespace)
        );
        assert_eq!(
            Capability::read("/priv/app\\..\\secret").unwrap_err(),
            CapabilityParseError::InvalidScope(StoragePathError::Backslash)
        );
    }

    #[test]
    fn capability_scope_rejects_wire_delimiters() {
        assert_eq!(
            Capability::read("/pub/a:b").unwrap_err(),
            CapabilityParseError::InvalidScopeDelimiter(':')
        );
        assert_eq!(
            Capability::read("/pub/a,b").unwrap_err(),
            CapabilityParseError::InvalidScopeDelimiter(',')
        );
    }

    #[test]
    fn parse_from_string_list() {
        // From a comma-separated string:
        let parsed = "/:rw,/pub/my-cool-app/:r"
            .parse::<Capabilities>()
            .unwrap()
            .normalize();
        let built = Capabilities::builder()
            .read_write("/") // "/:rw"
            .unwrap()
            .read("/pub/my-cool-app/") // "/pub/my-cool-app/:r"
            .unwrap()
            .finish();

        assert_eq!(parsed, built);
    }

    #[test]
    fn parse_errors_are_informative() {
        // Invalid scope (doesn't start with '/'):
        let error = "not/abs:rw".parse::<Capability>().unwrap_err();
        assert_eq!(
            error,
            CapabilityParseError::InvalidScope(StoragePathError::NotAbsolute)
        );

        // Invalid format (missing ':'):
        let error = "/pub/my.app".parse::<Capability>().unwrap_err();
        assert_eq!(error, CapabilityParseError::InvalidFormat);

        // Missing actions:
        let error = "/pub/my.app:".parse::<Capability>().unwrap_err();
        assert_eq!(error, CapabilityParseError::MissingActions);

        // Invalid action:
        let error = "/pub/my.app:rx".parse::<Capability>().unwrap_err();
        assert_eq!(error, CapabilityParseError::InvalidAction('x'));
    }

    #[test]
    fn capabilities_reports_invalid_entry() {
        let error = "/pub/app/:w,missing-leading-slash:r,/priv/file.txt:x"
            .parse::<Capabilities>()
            .unwrap_err();

        assert_eq!(error.position, 2);
        assert_eq!(error.entry, "missing-leading-slash:r");
        assert_eq!(
            error.source,
            CapabilityParseError::InvalidScope(StoragePathError::NotAbsolute)
        );
        assert_eq!(
            error.to_string(),
            "invalid capability at position 2 (`missing-leading-slash:r`): invalid capability scope: path must be absolute"
        );
    }

    #[test]
    fn capabilities_rejects_empty_entries() {
        for input in [",/:r", "/:r,", "/:r,,/:w"] {
            assert!(input.parse::<Capabilities>().is_err(), "accepted {input}");
        }
    }

    #[test]
    fn capabilities_accepts_empty_list() {
        assert_eq!("".parse::<Capabilities>(), Ok(Capabilities::default()));
    }

    #[test]
    fn caps_builder_finish_normalizes() {
        let caps = Capabilities::builder()
            .read("/pub/example.com/")
            .unwrap()
            .write("/pub/example.com/")
            .unwrap()
            .finish();

        assert_eq!(caps.to_string(), "/pub/example.com/:rw");
    }

    #[test]
    fn capabilities_from_url_parses_caps_parameter() {
        let url = Url::parse(
            "https://example.test?caps=/pub/example.com/:rw,/pub/example.com/documents:w",
        )
        .unwrap();
        let caps = Capabilities::try_from_caps_url(&url).unwrap();

        assert_eq!(
            caps.to_string(),
            "/pub/example.com/:rw,/pub/example.com/documents:w"
        );
    }

    #[test]
    fn capabilities_from_url_rejects_invalid_entry() {
        let url = Url::parse("https://example.test?caps=/:r,invalid:w").unwrap();
        let error = Capabilities::try_from_caps_url(&url).unwrap_err();

        assert_eq!(error.position, 2);
        assert_eq!(error.entry, "invalid:w");
    }

    #[test]
    fn normalization_merges_actions_and_removes_covered_scopes() {
        let caps = Capabilities::from(vec![
            Capability::read("/pub/example.com/").unwrap(),
            Capability::write("/pub/example.com/").unwrap(),
            Capability::write("/pub/example.com/subfolder").unwrap(),
            Capability::read("/priv/other").unwrap(),
        ])
        .normalize();

        assert_eq!(caps.to_string(), "/pub/example.com/:rw,/priv/other:r");
    }

    #[test]
    fn capabilities_len_and_is_empty() {
        let empty = Capabilities::builder().finish();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let one = Capabilities::builder().read("/").unwrap().finish();
        assert!(!one.is_empty());
        assert_eq!(one.len(), 1);
    }

    // Requires dev-dependency: serde_json
    #[test]
    fn serde_roundtrip_as_string() {
        let caps = Capabilities::builder()
            .read_write("/pub/my-cool-app/")
            .unwrap()
            .read("/pub/file.txt")
            .unwrap()
            .finish();

        let json = serde_json::to_string(&caps).unwrap();
        // Serialized as a single string:
        assert_eq!(json, "\"/pub/my-cool-app/:rw,/pub/file.txt:r\"");

        let back: Capabilities = serde_json::from_str(&json).unwrap();
        assert_eq!(back, caps);
    }

    #[test]
    fn serde_rejects_invalid_capability_entry() {
        let error = serde_json::from_str::<Capabilities>(r#""/:r,invalid:w""#).unwrap_err();

        assert!(error.to_string().contains("invalid:w"));
    }

    // --- scope_covers_path: trailing slash semantics ---
    //
    // The trailing `/` on a scope is significant. A directory scope
    // (`/pub/app/`) covers itself and any path inside it. A file scope
    // (`/pub/app`) covers only the exact path — never descendants and never
    // string-prefix neighbours like `/pub/app-evil`. Regression coverage
    // for the e2e auth tests, which grant `/pub/pubky.app/:rw` and require
    // `PUT /pub/pubky.app` to be denied.

    fn dir(scope: &str) -> Capability {
        Capability::write(scope).unwrap()
    }

    fn path(value: &str) -> StoragePath {
        StoragePath::new(value).unwrap()
    }

    #[test]
    fn directory_scope_covers_itself() {
        assert!(dir("/pub/app/").scope_covers_path(&path("/pub/app/")));
    }

    #[test]
    fn directory_scope_covers_descendants() {
        assert!(dir("/pub/app/").scope_covers_path(&path("/pub/app/foo")));
        assert!(dir("/pub/app/").scope_covers_path(&path("/pub/app/sub/bar.txt")));
    }

    #[test]
    fn directory_scope_does_not_cover_parent_path_without_trailing_slash() {
        // Regression: `/pub/app/` (the directory) is a different resource
        // from `/pub/app` (a file at the parent level). The e2e auth tests
        // grant `/pub/pubky.app/:rw` and expect `PUT /pub/pubky.app` to 403.
        assert!(!dir("/pub/app/").scope_covers_path(&path("/pub/app")));
        assert!(!dir("/pub/pubky.app/").scope_covers_path(&path("/pub/pubky.app")));
    }

    #[test]
    fn directory_scope_does_not_cover_sibling() {
        assert!(!dir("/pub/app/").scope_covers_path(&path("/pub/other/file")));
    }

    #[test]
    fn directory_scope_does_not_cover_string_prefix_sibling() {
        // Even with a directory scope, a string-prefix sibling like
        // `/pub/app-evil/...` is not inside `/pub/app/`.
        assert!(!dir("/pub/app/").scope_covers_path(&path("/pub/app-evil/file")));
    }

    #[test]
    fn file_scope_covers_only_exact_path() {
        assert!(dir("/pub/file.txt").scope_covers_path(&path("/pub/file.txt")));
    }

    #[test]
    fn file_scope_does_not_cover_descendants() {
        // A file scope is not a namespace prefix — granting `/pub/app:rw`
        // does not grant access to `/pub/app/inside`. To grant the directory,
        // use `/pub/app/`.
        assert!(!dir("/pub/app").scope_covers_path(&path("/pub/app/inside")));
    }

    #[test]
    fn file_scope_rejects_prefix_attack() {
        // The original motivation for moving away from `path.starts_with(scope)`.
        assert!(!dir("/pub/app").scope_covers_path(&path("/pub/app-evil/file")));
        assert!(!dir("/pub/app").scope_covers_path(&path("/pub/appended")));
    }

    #[test]
    fn root_scope_covers_any_path() {
        let root = Capability::root();
        assert!(root.scope_covers_path(&path("/")));
        assert!(root.scope_covers_path(&path("/pub/anything")));
        assert!(root.scope_covers_path(&path("/dav/some/file.txt")));
    }
}

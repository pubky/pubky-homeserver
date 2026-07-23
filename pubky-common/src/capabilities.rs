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
//! ## Builder ergonomics
//!
//! ```rust
//! use pubky_common::capabilities::{Capability, Capabilities};
//!
//! // Single-cap builder
//! let cap = Capability::builder("/pub/my-cool-app/")
//!     .read()
//!     .write()
//!     .finish();
//! assert_eq!(cap.to_string(), "/pub/my-cool-app/:rw");
//!
//! // Multiple caps builder
//! let caps = Capabilities::builder()
//!     .read_write("/pub/my-cool-app/")
//!     .read("/pub/foo.txt")
//!     .finish();
//! assert_eq!(caps.to_string(), "/pub/my-cool-app/:rw,/pub/foo.txt:r");
//! ```

use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, fmt::Display, str::FromStr};
use url::Url;

/// A single capability: a `scope` and the allowed `actions` within it.
///
/// The wire/string representation is `"<scope>:<actions>"`, see module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Capability {
    /// Scope of resources (e.g. a directory or file). Must start with `/`.
    pub scope: String,
    /// Allowed actions within `scope`. Serialized as a compact action string (e.g. `"rw"`).
    pub actions: Vec<Action>,
}

impl Capability {
    /// Shorthand for a root capability at `/` with read+write.
    ///
    /// Equivalent to `Capability { scope: "/".into(), actions: vec![Read, Write] }`.
    ///
    /// ```
    /// use pubky_common::capabilities::Capability;
    /// assert_eq!(Capability::root().to_string(), "/:rw");
    /// ```
    pub fn root() -> Self {
        Capability {
            scope: "/".to_string(),
            actions: vec![Action::Read, Action::Write],
        }
    }

    // ---- Shortcut constructors

    /// Construct a read-only capability for `scope`.
    ///
    /// The scope is normalized to start with `/` if it does not already.
    ///
    /// ```
    /// use pubky_common::capabilities::Capability;
    /// assert_eq!(Capability::read("pub/my.app").to_string(), "/pub/my.app:r");
    /// ```
    #[inline]
    pub fn read<S: Into<String>>(scope: S) -> Self {
        Self::builder(scope).read().finish()
    }

    /// Construct a write-only capability for `scope`.
    ///
    /// ```
    /// use pubky_common::capabilities::Capability;
    /// assert_eq!(Capability::write("/pub/tmp").to_string(), "/pub/tmp:w");
    /// ```
    #[inline]
    pub fn write<S: Into<String>>(scope: S) -> Self {
        Self::builder(scope).write().finish()
    }

    /// Construct a read+write capability for `scope`.
    ///
    /// ```
    /// use pubky_common::capabilities::Capability;
    /// assert_eq!(Capability::read_write("/").to_string(), "/:rw");
    /// ```
    #[inline]
    pub fn read_write<S: Into<String>>(scope: S) -> Self {
        Self::builder(scope).read().write().finish()
    }

    /// Start building a single capability for `scope`.
    ///
    /// The scope is normalized to have a leading `/`.
    ///
    /// ```
    /// use pubky_common::capabilities::Capability;
    /// let cap = Capability::builder("pub/my.app").read().finish();
    /// assert_eq!(cap.to_string(), "/pub/my.app:r");
    /// ```
    pub fn builder<S: Into<String>>(scope: S) -> CapabilityBuilder {
        CapabilityBuilder {
            scope: normalize_scope(scope.into()),
            actions: BTreeSet::new(),
        }
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
    pub fn scope_covers_path(&self, path: &str) -> bool {
        if self.scope == path {
            return true;
        }
        // Only directory scopes (trailing `/`) cover descendant paths.
        // For a file scope, only exact-match (handled above) is allowed.
        self.scope.ends_with('/') && path.starts_with(&self.scope)
    }

    /// Whether this capability fully covers `other` — i.e. the scope is equal or
    /// broader, and every action (read/write) in `other` is also present in `self`.
    fn covers(&self, other: &Capability) -> bool {
        if !self.scope_covers_path(&other.scope) {
            return false;
        }

        other
            .actions
            .iter()
            .all(|action| self.actions.contains(action))
    }
}

/// Fluent builder for a single [`Capability`].
///
/// Use [`Capability::builder`] to construct, then chain `.read()/.write()` and `.finish()`.
#[derive(Debug, Default)]
pub struct CapabilityBuilder {
    scope: String,
    actions: BTreeSet<Action>,
}

impl CapabilityBuilder {
    /// Allow **read** (GET) within the scope.
    pub fn read(mut self) -> Self {
        self.actions.insert(Action::Read);
        self
    }

    /// Allow **write** (PUT/POST/DELETE) within the scope.
    pub fn write(mut self) -> Self {
        self.actions.insert(Action::Write);
        self
    }

    /// Allow a specific action. Useful if more actions are added in the future.
    pub fn allow(mut self, action: Action) -> Self {
        self.actions.insert(action);
        self
    }

    /// Finalize and produce the [`Capability`].
    ///
    /// Actions are de-duplicated and emitted in a stable order.
    pub fn finish(self) -> Capability {
        let v: Vec<Action> = self.actions.into_iter().collect();
        // BTreeSet sorts; keep stable & dedup’d
        Capability {
            scope: self.scope,
            actions: v,
        }
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

        if !scope.starts_with('/') {
            return Err(CapabilityParseError::InvalidScope);
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
            scope: scope.to_string(),
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
    /// The scope does not start with `/`.
    #[error("capability scope must start with `/`")]
    InvalidScope,
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
    ///     Capability::read("/pub/"),
    ///     Capability::write("/pub/"),
    ///     Capability::read("/pub/file.txt"),
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
    /// let caps = Capabilities::builder().read_write("/").finish();
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
    ///     Capability::read("/foo"),
    ///     Capability::write("/bar/"),
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
/// capabilities with `.cap()`, or use `.capability(scope, |b| ...)` to build inline.
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

    /// Build a capability inline and push it:
    ///
    /// ```
    /// use pubky_common::capabilities::Capabilities;
    /// let caps = Capabilities::builder()
    ///     .capability("/pub/my-cool-app/", |b| b.read().write())
    ///     .finish();
    /// assert_eq!(caps.to_string(), "/pub/my-cool-app/:rw");
    /// ```
    pub fn capability<F>(mut self, scope: impl Into<String>, f: F) -> Self
    where
        F: FnOnce(CapabilityBuilder) -> CapabilityBuilder,
    {
        let cap = f(Capability::builder(scope)).finish();
        self.caps.push(cap);
        self
    }

    /// Add a read-only capability for `scope`.
    pub fn read(mut self, scope: impl Into<String>) -> Self {
        self.caps.push(Capability::read(scope));
        self
    }

    /// Add a write-only capability for `scope`.
    pub fn write(mut self, scope: impl Into<String>) -> Self {
        self.caps.push(Capability::write(scope));
        self
    }

    /// Add a read+write capability for `scope`.
    pub fn read_write(mut self, scope: impl Into<String>) -> Self {
        self.caps.push(Capability::read_write(scope));
        self
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

fn normalize_scope(mut s: String) -> String {
    if !s.starts_with('/') {
        s.insert(0, '/');
    }
    s
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
    fn pubky_caps() {
        let cap = Capability {
            scope: "/pub/pubky.app/".to_string(),
            actions: vec![Action::Read, Action::Write],
        };

        // Read and write within directory `/pub/pubky.app/`.
        let expected_string = "/pub/pubky.app/:rw";

        assert_eq!(cap.to_string(), expected_string);

        assert_eq!(expected_string.parse(), Ok(cap))
    }

    #[test]
    fn root_capability_helper() {
        let cap = Capability::root();
        assert_eq!(cap.scope, "/");
        assert_eq!(cap.actions, vec![Action::Read, Action::Write]);
        assert_eq!(cap.to_string(), "/:rw");
        // And it round-trips through the string form:
        assert_eq!("/:rw".parse(), Ok(cap));
    }

    #[test]
    fn single_capability_via_builder_and_shortcuts() {
        // Full builder:
        let cap1 = Capability::builder("/pub/my-cool-app/")
            .read()
            .write()
            .finish();
        assert_eq!(cap1.to_string(), "/pub/my-cool-app/:rw");

        // Shortcuts:
        let cap_rw = Capability::read_write("/pub/my-cool-app/");
        let cap_r = Capability::read("/pub/file.txt");
        let cap_w = Capability::write("/pub/uploads/");

        assert_eq!(cap_rw, cap1);
        assert_eq!(cap_r.to_string(), "/pub/file.txt:r");
        assert_eq!(cap_w.to_string(), "/pub/uploads/:w");
    }

    #[test]
    fn multiple_caps_with_capsbuilder() {
        let caps = Capabilities::builder()
            .read("/pub/my-cool-app/") // "/pub/my-cool-app/:r"
            .write("/pub/uploads/") // "/pub/uploads/:w"
            .read_write("/pub/my-cool-app/data/") // "/pub/my-cool-app/data/:rw"
            .finish();

        // String form is comma-separated, in insertion order:
        assert_eq!(
            caps.to_string(),
            "/pub/my-cool-app/:r,/pub/uploads/:w,/pub/my-cool-app/data/:rw"
        );

        // Contains checks:
        assert!(caps.contains(&Capability::read("/pub/my-cool-app/")));
        assert!(caps.contains(&Capability::write("/pub/uploads/")));
        assert!(caps.contains(&Capability::read_write("/pub/my-cool-app/data/")));
        assert!(!caps.contains(&Capability::write("/nope")));
    }

    #[test]
    fn build_with_inline_capability_closure() {
        // Build a capability inline with fine-grained control, then push it:
        let caps = Capabilities::builder()
            .capability("/pub/my-cool-app/", |c| c.read().write())
            .finish();

        assert_eq!(caps.to_string(), "/pub/my-cool-app/:rw");
    }

    #[test]
    fn action_dedup_and_order_are_stable() {
        // Insert actions in noisy order; builder dedups & sorts (Read < Write).
        let cap = Capability::builder("/")
            .write()
            .read()
            .read()
            .write()
            .finish();
        assert_eq!(cap.actions, vec![Action::Read, Action::Write]);
        assert_eq!(cap.to_string(), "/:rw");
    }

    #[test]
    fn normalize_scope_adds_leading_slash() {
        // No leading slash? The helpers normalize it.
        let cap = Capability::read("pub/my.app");
        assert_eq!(cap.scope, "/pub/my.app");
        assert_eq!(cap.to_string(), "/pub/my.app:r");

        // CapsBuilder helpers also normalize:
        let caps = Capabilities::builder()
            .read_write("pub/my-cool-app/data")
            .finish();
        assert_eq!(caps.to_string(), "/pub/my-cool-app/data:rw");
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
            .read("/pub/my-cool-app/") // "/pub/my-cool-app/:r"
            .finish();

        assert_eq!(parsed, built);
    }

    #[test]
    fn parse_errors_are_informative() {
        // Invalid scope (doesn't start with '/'):
        let error = "not/abs:rw".parse::<Capability>().unwrap_err();
        assert_eq!(error, CapabilityParseError::InvalidScope);

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
        assert_eq!(error.source, CapabilityParseError::InvalidScope);
        assert_eq!(
            error.to_string(),
            "invalid capability at position 2 (`missing-leading-slash:r`): capability scope must start with `/`"
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
    fn redundant_capabilities_builder_dedup() {
        let caps = Capabilities::builder()
            .read_write("/pub/example.com/")
            .read_write("/pub/example.com/")
            .write("/pub/example.com/subfolder")
            .finish()
            .normalize();

        assert_eq!(caps.to_string(), "/pub/example.com/:rw");
    }

    #[test]
    fn redundant_capabilities_string_dedup() {
        let parsed = "/pub/example.com/:rw,/pub/example.com/:rw,/pub/example.com/subfolder:w"
            .parse::<Capabilities>()
            .unwrap()
            .normalize();

        let caps = Capabilities::builder()
            .read_write("/pub/example.com/")
            .finish();

        assert_eq!(caps.to_string(), "/pub/example.com/:rw");
        assert_eq!(parsed, caps);
    }

    #[test]
    fn redundant_capabilities_from_url_dedup() {
        let url = Url::parse(
            "https://example.test?caps=/pub/example.com/:rw,/pub/example.com/documents:w",
        )
        .unwrap();
        let caps = Capabilities::try_from_caps_url(&url).unwrap().normalize();

        assert_eq!(caps.to_string(), "/pub/example.com/:rw");
    }

    #[test]
    fn capabilities_from_url_rejects_invalid_entry() {
        let url = Url::parse("https://example.test?caps=/:r,invalid:w").unwrap();
        let error = Capabilities::try_from_caps_url(&url).unwrap_err();

        assert_eq!(error.position, 2);
        assert_eq!(error.entry, "invalid:w");
    }

    #[test]
    fn redundant_capabilities_merge_actions() {
        let caps = Capabilities::builder()
            .read("/pub/example.com/")
            .write("/pub/example.com/")
            .finish()
            .normalize();

        assert_eq!(caps.to_string(), "/pub/example.com/:rw");
    }

    #[test]
    fn capabilities_normalize_dedups_from_vec() {
        let caps = Capabilities::from(vec![
            Capability::read_write("/pub/example.com/"),
            Capability::write("/pub/example.com/subfolder"),
            Capability::read("/pub/example.com/"),
        ])
        .normalize();

        assert_eq!(caps.to_string(), "/pub/example.com/:rw");
    }

    #[test]
    fn capabilities_len_and_is_empty() {
        let empty = Capabilities::builder().finish();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);

        let one = Capabilities::builder().read("/").finish();
        assert!(!one.is_empty());
        assert_eq!(one.len(), 1);
    }

    // Requires dev-dependency: serde_json
    #[test]
    fn serde_roundtrip_as_string() {
        let caps = Capabilities::builder()
            .read_write("/pub/my-cool-app/")
            .read("/pub/file.txt")
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
        Capability::write(scope)
    }

    #[test]
    fn directory_scope_covers_itself() {
        assert!(dir("/pub/app/").scope_covers_path("/pub/app/"));
    }

    #[test]
    fn directory_scope_covers_descendants() {
        assert!(dir("/pub/app/").scope_covers_path("/pub/app/foo"));
        assert!(dir("/pub/app/").scope_covers_path("/pub/app/sub/bar.txt"));
    }

    #[test]
    fn directory_scope_does_not_cover_parent_path_without_trailing_slash() {
        // Regression: `/pub/app/` (the directory) is a different resource
        // from `/pub/app` (a file at the parent level). The e2e auth tests
        // grant `/pub/pubky.app/:rw` and expect `PUT /pub/pubky.app` to 403.
        assert!(!dir("/pub/app/").scope_covers_path("/pub/app"));
        assert!(!dir("/pub/pubky.app/").scope_covers_path("/pub/pubky.app"));
    }

    #[test]
    fn directory_scope_does_not_cover_sibling() {
        assert!(!dir("/pub/app/").scope_covers_path("/pub/other/file"));
    }

    #[test]
    fn directory_scope_does_not_cover_string_prefix_sibling() {
        // Even with a directory scope, a string-prefix sibling like
        // `/pub/app-evil/...` is not inside `/pub/app/`.
        assert!(!dir("/pub/app/").scope_covers_path("/pub/app-evil/file"));
    }

    #[test]
    fn file_scope_covers_only_exact_path() {
        assert!(dir("/pub/file.txt").scope_covers_path("/pub/file.txt"));
    }

    #[test]
    fn file_scope_does_not_cover_descendants() {
        // A file scope is not a namespace prefix — granting `/pub/app:rw`
        // does not grant access to `/pub/app/inside`. To grant the directory,
        // use `/pub/app/`.
        assert!(!dir("/pub/app").scope_covers_path("/pub/app/inside"));
    }

    #[test]
    fn file_scope_rejects_prefix_attack() {
        // The original motivation for moving away from `path.starts_with(scope)`.
        assert!(!dir("/pub/app").scope_covers_path("/pub/app-evil/file"));
        assert!(!dir("/pub/app").scope_covers_path("/pub/appended"));
    }

    #[test]
    fn root_scope_covers_any_path() {
        let root = Capability::root();
        assert!(root.scope_covers_path("/"));
        assert!(root.scope_covers_path("/pub/anything"));
        assert!(root.scope_covers_path("/dav/some/file.txt"));
    }
}

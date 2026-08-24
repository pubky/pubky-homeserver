use serde::{Deserialize, Serialize};
use std::{fmt::Display, str::FromStr};

/// A wrapper around fast_glob to allow serialize/deserialize.
/// Pattern matches glob patterns.
///
/// Syntax - Meaning
/// `?` - Matches any single character.
/// `*` - Matches zero or more characters, except for path separators (e.g. /).
/// `**` - Matches zero or more characters, including path separators. Must match a complete path segment (i.e. followed by a / or the end of the pattern).
/// `[ab]` - Matches one of the characters contained in the brackets. Character ranges, e.g. `[a-z]` are also supported. Use `[!ab]` or `[^ab]` to match any character except those contained in the brackets.
/// `{a,b}` - Matches one of the patterns contained in the braces. Any of the wildcard characters can be used in the sub-patterns. Braces may be nested up to 10 levels deep.
/// `!` - When at the start of the glob, this negates the result. Multiple `!` characters negate the glob multiple times.
/// `\` - A backslash character may be used to escape any of the above special characters.
#[derive(Debug, Clone)]
pub struct GlobPattern(pub String);

impl GlobPattern {
    /// Create a new glob pattern.
    pub fn new(pattern: &str) -> Self {
        Self(pattern.to_string())
    }

    /// Check if the path matches the glob pattern.
    pub fn is_match(&self, path: &str) -> bool {
        fast_glob::glob_match(&self.0, path)
    }
}

impl std::hash::Hash for GlobPattern {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_str().hash(state);
    }
}

impl FromStr for GlobPattern {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(GlobPattern(s.to_string()))
    }
}

impl Display for GlobPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.as_str())
    }
}

impl Serialize for GlobPattern {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for GlobPattern {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        GlobPattern::from_str(&s).map_err(serde::de::Error::custom)
    }
}

impl PartialEq for GlobPattern {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_str() == other.0.as_str()
    }
}

impl Eq for GlobPattern {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glob_pattern() {
        let glob_pattern = GlobPattern::from_str("/pub/**").unwrap();
        assert!(glob_pattern.is_match("/pub/test.txt"));
        assert!(glob_pattern.is_match("/pub/test/test.txt"));
        assert!(!glob_pattern.is_match("/priv/test.pdf"));
        assert!(!glob_pattern.is_match("/session/test.txt"));
    }

    #[test]
    fn test_glob_pattern2() {
        let glob_pattern = GlobPattern::from_str("/events/").unwrap();
        assert!(glob_pattern.is_match("/events/"));
    }

    #[test]
    fn test_glob_pattern3() {
        let glob_pattern = GlobPattern::from_str("/pub/**").unwrap();
        assert!(glob_pattern.is_match("/pub/test.txt"));
        assert!(glob_pattern.is_match("/pub/test/test.txt"));
        assert!(glob_pattern.is_match("/pub/"));
    }

    #[test]
    fn test_glob_pattern4() {
        let glob_pattern = GlobPattern::from_str("/pub/**/update").unwrap();
        assert!(glob_pattern.is_match("/pub/test.txt/update"));
        assert!(glob_pattern.is_match("/pub/test/test.txt/update"));
        assert!(!glob_pattern.is_match("/pub/test/test.txt"));
        assert!(!glob_pattern.is_match("/pub/"));
    }

    #[test]
    fn test_glob_pattern5() {
        let glob_pattern = GlobPattern::from_str("/pub/**/update/*").unwrap();
        assert!(glob_pattern.is_match("/pub/test.txt/update/test.txt"));
        assert!(glob_pattern.is_match("/pub/test/test.txt/update/test.txt"));
        assert!(!glob_pattern.is_match("/pub/test/test.txt"));
        assert!(!glob_pattern.is_match("/pub/"));
    }
}

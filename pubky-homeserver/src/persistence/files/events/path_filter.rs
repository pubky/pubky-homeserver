//! Authorized path filter for the event stream, shared by the route and the repository.

use sea_query::{Expr, LikeExpr, SimpleExpr};

use crate::shared::webdav::StoragePath;

use super::events_repository::{EventIden, EVENT_TABLE};

/// A single authorized path filter for the event stream.
///
/// Wraps a validated [`StoragePath`]. A file path (no trailing `/`) matches only its exact path,
/// while a directory path (trailing `/`) matches that directory and all of its
/// descendants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathFilter(StoragePath);

impl From<StoragePath> for PathFilter {
    fn from(path: StoragePath) -> Self {
        Self(path)
    }
}

impl PathFilter {
    /// Whether `path` is selected by this filter.
    pub fn matches(&self, path: &str) -> bool {
        let prefix = self.0.as_str();
        if self.0.is_directory() {
            path.starts_with(prefix)
        } else {
            path == prefix
        }
    }

    /// SQL predicate selecting rows whose `path` column matches this filter.
    /// File filters use exact equality; directory filters use an escaped
    /// `LIKE '<dir>%'` so `_`/`%`/`\` in the stored prefix are matched
    /// literally and cannot widen the match.
    pub(super) fn to_condition(&self) -> SimpleExpr {
        let path = self.0.as_str();
        if self.0.is_directory() {
            let escaped = path
                .replace('\\', "\\\\")
                .replace('_', "\\_")
                .replace('%', "\\%");
            let like_pattern = format!("{escaped}%");
            Expr::col((EVENT_TABLE, EventIden::Path)).like(LikeExpr::new(like_pattern).escape('\\'))
        } else {
            Expr::col((EVENT_TABLE, EventIden::Path)).eq(path)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pf(s: &str) -> PathFilter {
        StoragePath::new(s).unwrap().into()
    }

    #[test]
    fn path_filter_matches_file_and_dir_boundaries() {
        let file = pf("/priv/app");
        assert!(file.matches("/priv/app"));
        assert!(!file.matches("/priv/app/x")); // a file scope has no descendants
        assert!(!file.matches("/priv/app-evil")); // sibling-prefix
        assert!(!file.matches("/priv/ap"));

        let dir = pf("/priv/app/");
        assert!(dir.matches("/priv/app/"));
        assert!(dir.matches("/priv/app/x"));
        assert!(dir.matches("/priv/app/sub/y"));
        assert!(!dir.matches("/priv/app")); // the parent file
        assert!(!dir.matches("/priv/app-evil/x")); // sibling-prefix
        assert!(!dir.matches("/priv/other/x"));
    }

    #[test]
    fn trailing_slash_selects_file_vs_dir_matching() {
        // The trailing slash is the only thing that distinguishes a directory
        // (prefix) filter from a file (exact) filter for the same base path.
        assert!(pf("/priv/app/").matches("/priv/app/x"));
        assert!(!pf("/priv/app").matches("/priv/app/x"));
        assert!(pf("/priv/app").matches("/priv/app"));
    }
}

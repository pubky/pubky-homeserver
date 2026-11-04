//! `LIKE` patterns whose literal part is matched as written.

use sea_query::LikeExpr;

/// `LIKE` pattern matching values that start with `prefix`.
///
/// `\`, `_` and `%` in the prefix are escaped so they match literally and
/// cannot widen the match: listing `a%b/` must not return `a%20b/`, nor
/// `a_b/` return `aXb/`. A `StoragePath` never carries a `\`, but escaping
/// it keeps the helper correct for any prefix.
pub(crate) fn starts_with(prefix: &str) -> LikeExpr {
    let escaped = prefix
        .replace('\\', "\\\\")
        .replace('_', "\\_")
        .replace('%', "\\%");
    LikeExpr::new(format!("{escaped}%")).escape('\\')
}

use axum::{body::Body, http::StatusCode, response::Response};

use crate::constants::{DEFAULT_LIST_LIMIT, DEFAULT_MAX_LIST_LIMIT};

/// Apply the default list limit and cap it at the maximum, preserving explicit zero.
pub(crate) fn effective_list_limit(limit: Option<u16>) -> u16 {
    std::cmp::min(limit.unwrap_or(DEFAULT_LIST_LIMIT), DEFAULT_MAX_LIST_LIMIT)
}

/// Split rows fetched with `limit + 1` into a page of at most `limit` rows and
/// the cursor for the next page, taken from the page's last row. The extra row
/// only signals that another page exists.
pub(crate) fn split_list_page<T, C>(
    mut rows: Vec<T>,
    limit: u16,
    cursor: impl Fn(&T) -> C,
) -> (Vec<T>, Option<C>) {
    if rows.len() > limit as usize {
        rows.truncate(limit as usize);
        let next_cursor = rows.last().map(cursor);
        (rows, next_cursor)
    } else {
        (rows, None)
    }
}

/// Parse a boolean value from a string.
/// Returns an error if the value is not a valid boolean.
pub fn parse_bool(value: &str) -> Result<bool, Box<Response>> {
    match value.to_lowercase().as_str() {
        "true" => Ok(true),
        "yes" => Ok(true),
        "1" => Ok(true),
        "" => Ok(true),
        "false" => Ok(false),
        "no" => Ok(false),
        "0" => Ok(false),
        _ => Err(Box::new(
            Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Invalid boolean parameter"))
                .unwrap(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_list_page_full_page_yields_cursor() {
        let (items, next) = split_list_page(vec![1, 2, 3], 2, |n| n * 10);
        assert_eq!(items, vec![1, 2]);
        assert_eq!(next, Some(20));
    }

    #[test]
    fn split_list_page_last_page_has_no_cursor() {
        let (items, next) = split_list_page(vec![1, 2], 2, |n| n * 10);
        assert_eq!(items, vec![1, 2]);
        assert_eq!(next, None);

        let (items, next) = split_list_page(Vec::<i32>::new(), 2, |n| n * 10);
        assert!(items.is_empty());
        assert_eq!(next, None);
    }

    #[test]
    fn split_list_page_zero_limit_yields_empty_page() {
        let (items, next) = split_list_page(vec![1], 0, |n| n * 10);
        assert!(items.is_empty());
        assert_eq!(next, None);
    }
}

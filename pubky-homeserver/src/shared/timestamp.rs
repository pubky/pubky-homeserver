//! UTC timestamps for SQL `TIMESTAMP` columns and the API responses that show them.
//!
//! The formatting reproduces chrono's output byte for byte, because the homeserver
//! used chrono before and clients may parse these strings strictly: seconds are
//! followed by 3, 6 or 9 fractional digits, whichever is the shortest exact one,
//! and by none when the fraction is zero.

use serde::Serializer;
use time::{OffsetDateTime, PlainDateTime};

/// The current UTC time, as stored in a `TIMESTAMP` (without time zone) column.
pub(crate) fn now_naive_utc() -> PlainDateTime {
    let now = OffsetDateTime::now_utc();
    PlainDateTime::new(now.date(), now.time())
}

/// ISO 8601 without a UTC offset, e.g. `2026-10-22T10:11:12.123456`.
pub(crate) fn to_iso8601(datetime: &PlainDateTime) -> String {
    let fraction = match datetime.nanosecond() {
        0 => String::new(),
        nanos if nanos % 1_000_000 == 0 => format!(".{:03}", nanos / 1_000_000),
        nanos if nanos % 1_000 == 0 => format!(".{:06}", nanos / 1_000),
        nanos => format!(".{nanos:09}"),
    };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{fraction}",
        datetime.year(),
        u8::from(datetime.month()),
        datetime.day(),
        datetime.hour(),
        datetime.minute(),
        datetime.second(),
    )
}

/// RFC 3339 with an explicit `+00:00` offset, e.g. `2026-10-22T10:11:12.123456+00:00`.
pub(crate) fn to_rfc3339_utc(datetime: &PlainDateTime) -> String {
    format!("{}+00:00", to_iso8601(datetime))
}

/// Serde `serialize_with` for [`to_iso8601`].
pub(crate) fn serialize_iso8601<S: Serializer>(
    datetime: &PlainDateTime,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&to_iso8601(datetime))
}

/// Serde `serialize_with` for an optional [`to_iso8601`] value; `None` is `null`.
pub(crate) fn serialize_option_iso8601<S: Serializer>(
    datetime: &Option<PlainDateTime>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match datetime {
        Some(datetime) => serialize_iso8601(datetime, serializer),
        None => serializer.serialize_none(),
    }
}

#[cfg(test)]
mod tests {
    use time::macros::datetime;

    use super::*;

    #[test]
    fn iso8601_matches_chrono_fraction_rules() {
        assert_eq!(
            to_iso8601(&datetime!(2026-10-22 10:11:12)),
            "2026-10-22T10:11:12"
        );
        assert_eq!(
            to_iso8601(&datetime!(2026-10-22 10:11:12.12)),
            "2026-10-22T10:11:12.120"
        );
        assert_eq!(
            to_iso8601(&datetime!(2026-10-22 10:11:12.120394)),
            "2026-10-22T10:11:12.120394"
        );
        assert_eq!(
            to_iso8601(&datetime!(2026-10-22 10:11:12.000000001)),
            "2026-10-22T10:11:12.000000001"
        );
        assert_eq!(
            to_iso8601(&datetime!(0001-02-03 04:05:06)),
            "0001-02-03T04:05:06"
        );
    }

    #[test]
    fn rfc3339_adds_utc_offset() {
        assert_eq!(
            to_rfc3339_utc(&datetime!(2026-10-22 10:11:12.120394)),
            "2026-10-22T10:11:12.120394+00:00"
        );
    }

    #[test]
    fn serializes_option_as_string_or_null() {
        #[derive(serde::Serialize)]
        struct Item {
            #[serde(serialize_with = "serialize_option_iso8601")]
            at: Option<PlainDateTime>,
        }
        let json = serde_json::to_string(&Item {
            at: Some(datetime!(2026-10-22 10:11:12)),
        });
        assert_eq!(json.unwrap(), r#"{"at":"2026-10-22T10:11:12"}"#);
        let json = serde_json::to_string(&Item { at: None });
        assert_eq!(json.unwrap(), r#"{"at":null}"#);
    }
}

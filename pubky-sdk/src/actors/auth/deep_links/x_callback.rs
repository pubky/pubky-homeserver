use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use url::Url;

/// Percent-encode callback values like JavaScript's `encodeURIComponent`.
///
/// Ring decodes callback parameters exactly once with `decodeURIComponent`, so
/// spaces must be emitted as `%20` rather than the form-encoded `+`.
const X_CALLBACK_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');

/// Optional x-callback-url metadata carried by a Pubky deep link.
///
/// Callback destinations are kept as strings rather than parsed [`Url`]s so
/// custom schemes and percent-encoded content round-trip exactly. They are
/// untrusted navigation hints; applications must decide whether and how to
/// open them. Authentication still completes through the encrypted relay.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct XCallbackParams {
    /// Human-readable name of the application requesting authorization.
    pub x_source: Option<String>,
    /// Destination to open after successful completion.
    pub x_success: Option<String>,
    /// Destination to open after an error.
    pub x_error: Option<String>,
    /// Destination to open after user cancellation or timeout.
    pub x_cancel: Option<String>,
}

impl XCallbackParams {
    /// Parse x-callback-url parameters from a URL's still-encoded query.
    ///
    /// Values are decoded exactly once. A literal `+` remains `+`, matching
    /// Pubky Ring's `decodeURIComponent` behavior. Legacy `callback` is used as
    /// a fallback only when `x-success` is absent.
    #[must_use]
    pub fn from_url(url: &Url) -> Self {
        let Some(query) = url.query() else {
            return Self::default();
        };

        let x_success = Self::raw_query_value(query, "x-success")
            .or_else(|| Self::raw_query_value(query, "callback"))
            .map(Self::decode_once);

        Self {
            x_source: Self::raw_query_value(query, "x-source").map(Self::decode_once),
            x_success,
            x_error: Self::raw_query_value(query, "x-error").map(Self::decode_once),
            x_cancel: Self::raw_query_value(query, "x-cancel").map(Self::decode_once),
        }
    }

    /// Return true when no callback parameters are present.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.x_source.is_none()
            && self.x_success.is_none()
            && self.x_error.is_none()
            && self.x_cancel.is_none()
    }

    /// Append canonical x-callback-url parameters to a URL.
    ///
    /// Existing query parameters are preserved. The legacy `callback` key is
    /// never emitted; parsed legacy values are canonicalized to `x-success`.
    pub fn append_to_url(&self, url: &mut Url) {
        if self.is_empty() {
            return;
        }

        let mut query = url.query().unwrap_or_default().to_owned();
        for (key, value) in [
            ("x-source", self.x_source.as_deref()),
            ("x-success", self.x_success.as_deref()),
            ("x-error", self.x_error.as_deref()),
            ("x-cancel", self.x_cancel.as_deref()),
        ] {
            let Some(value) = value else {
                continue;
            };

            if !query.is_empty() {
                query.push('&');
            }
            query.push_str(key);
            query.push('=');
            query.push_str(&utf8_percent_encode(value, X_CALLBACK_ENCODE_SET).to_string());
        }
        url.set_query(Some(&query));
    }

    fn raw_query_value<'a>(query: &'a str, key: &str) -> Option<&'a str> {
        query.split('&').find_map(|pair| {
            let (pair_key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (pair_key == key).then_some(value)
        })
    }

    fn decode_once(value: &str) -> String {
        if !Self::has_valid_percent_triplets(value) {
            return value.to_owned();
        }

        percent_decode_str(value)
            .decode_utf8()
            .map_or_else(|_| value.to_owned(), std::borrow::Cow::into_owned)
    }

    fn has_valid_percent_triplets(value: &str) -> bool {
        value.split('%').skip(1).all(|escape| {
            matches!(
                escape.as_bytes(),
                [first, second, ..]
                    if first.is_ascii_hexdigit() && second.is_ascii_hexdigit()
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_callback_params_exactly_once() {
        let url = Url::parse(
            "pubkyauth://signin?caps=%2F%3Arw&x-source=Bitkit%20Wallet&x-success=bitkit%3A%2F%2Fwallet%2Fcallback%3Fnonce%3Dabc%252F123%26state%3Dready&x-error=bitkit%3A%2F%2Fwallet%2Ferror%3Fnonce%3Dabc%26reason%3Ddenied&x-cancel=bitkit%3A%2F%2Fwallet%2Fcancel%3Fnonce%3Dabc",
        )
        .unwrap();

        assert_eq!(
            XCallbackParams::from_url(&url),
            XCallbackParams {
                x_source: Some("Bitkit Wallet".into()),
                x_success: Some("bitkit://wallet/callback?nonce=abc%2F123&state=ready".into()),
                x_error: Some("bitkit://wallet/error?nonce=abc&reason=denied".into()),
                x_cancel: Some("bitkit://wallet/cancel?nonce=abc".into()),
            }
        );
    }

    #[test]
    fn preserves_literal_plus_and_decodes_percent_encoded_space() {
        let url = Url::parse(
            "pubkyauth://signin?x-source=Bitkit+Wallet%20Mobile&x-success=bitkit%3A%2F%2Fcallback%3Fnonce%3Da%2Bb",
        )
        .unwrap();

        let callbacks = XCallbackParams::from_url(&url);
        assert_eq!(callbacks.x_source.as_deref(), Some("Bitkit+Wallet Mobile"));
        assert_eq!(
            callbacks.x_success.as_deref(),
            Some("bitkit://callback?nonce=a+b")
        );
    }

    #[test]
    fn x_success_takes_precedence_over_legacy_callback_even_when_empty() {
        let url =
            Url::parse("pubkyauth://signin?x-success=&callback=bitkit%3A%2F%2Flegacy").unwrap();

        assert_eq!(
            XCallbackParams::from_url(&url).x_success.as_deref(),
            Some("")
        );
    }

    #[test]
    fn uses_legacy_callback_as_success_fallback() {
        let url = Url::parse("pubkyauth://signin?callback=bitkit%3A%2F%2Flegacy").unwrap();

        assert_eq!(
            XCallbackParams::from_url(&url).x_success.as_deref(),
            Some("bitkit://legacy")
        );
    }

    #[test]
    fn appends_callbacks_with_ring_compatible_encoding_and_order() {
        let mut url = Url::parse("pubkyauth://signin?caps=%2F%3Arw").unwrap();
        let callbacks = XCallbackParams {
            x_source: Some("Bitkit Wallet".into()),
            x_success: Some("bitkit://callback?nonce=a+b&state=ready%20now".into()),
            x_error: Some("bitkit://error".into()),
            x_cancel: Some("bitkit://cancel".into()),
        };

        callbacks.append_to_url(&mut url);

        assert_eq!(
            url.as_str(),
            "pubkyauth://signin?caps=%2F%3Arw&x-source=Bitkit%20Wallet&x-success=bitkit%3A%2F%2Fcallback%3Fnonce%3Da%2Bb%26state%3Dready%2520now&x-error=bitkit%3A%2F%2Ferror&x-cancel=bitkit%3A%2F%2Fcancel"
        );
        assert_eq!(XCallbackParams::from_url(&url), callbacks);
    }

    #[test]
    fn canonicalizes_legacy_callback_when_appending() {
        let legacy = Url::parse("pubkyauth://signin?callback=bitkit%3A%2F%2Flegacy").unwrap();
        let callbacks = XCallbackParams::from_url(&legacy);
        let mut canonical = Url::parse("pubkyauth://signin").unwrap();

        callbacks.append_to_url(&mut canonical);

        assert_eq!(
            canonical.as_str(),
            "pubkyauth://signin?x-success=bitkit%3A%2F%2Flegacy"
        );
    }

    #[test]
    fn malformed_percent_encoding_is_left_unchanged() {
        let url = Url::parse("pubkyauth://signin?x-success=bitkit%3A%2F%2Fcallback%ZZ").unwrap();

        assert_eq!(
            XCallbackParams::from_url(&url).x_success.as_deref(),
            Some("bitkit%3A%2F%2Fcallback%ZZ")
        );
    }
}

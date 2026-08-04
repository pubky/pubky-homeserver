use std::{
    fmt::{self, Display},
    marker::PhantomData,
    str::FromStr,
};

use url::Url;

use super::{DeepLinkParseError, XCallbackParams, schemes::DeepLinkScheme};

/// Intent marker for typed Pubky deep links.
pub trait DeepLinkIntent {
    /// URI host value used as the deep-link intent.
    const NAME: &'static str;
}

/// Typed parameter set for a Pubky deep-link intent.
pub trait DeepLinkParams: Sized {
    /// Parse this parameter set from a URL.
    ///
    /// # Errors
    ///
    /// Returns [`DeepLinkParseError`] when required parameters are missing or malformed.
    fn parse(url: &Url) -> Result<Self, DeepLinkParseError>;

    /// Append this parameter set as URL query pairs.
    fn append_query_pairs(&self, url: &mut Url);
}

/// A typed Pubky deep link with a statically selected intent and parameter set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypedDeepLink<I, P> {
    scheme: DeepLinkScheme,
    params: P,
    x_callback: XCallbackParams,
    _intent: PhantomData<I>,
}

impl<I, P> TypedDeepLink<I, P> {
    /// Create a typed deep link from a scheme and typed params.
    pub fn new(scheme: DeepLinkScheme, params: P) -> Self {
        Self {
            scheme,
            params,
            x_callback: XCallbackParams::default(),
            _intent: PhantomData,
        }
    }
}

impl<I, P> TypedDeepLink<I, P>
where
    I: DeepLinkIntent,
    P: DeepLinkParams,
{
    /// Parse a typed deep link from a URL.
    ///
    /// # Errors
    ///
    /// Returns [`DeepLinkParseError`] when the URL scheme, intent, or parameters are invalid.
    pub fn parse_url(url: &Url) -> Result<Self, DeepLinkParseError> {
        let scheme = url.scheme().parse()?;
        if url.host_str().unwrap_or("") != I::NAME {
            return Err(DeepLinkParseError::InvalidIntent(I::NAME));
        }

        Ok(Self {
            scheme,
            params: P::parse(url)?,
            x_callback: XCallbackParams::from_url(url),
            _intent: PhantomData,
        })
    }

    /// Return the validated deep-link scheme.
    pub fn scheme(&self) -> DeepLinkScheme {
        self.scheme
    }

    /// Return the statically selected deep-link intent.
    pub fn intent(&self) -> &'static str {
        I::NAME
    }

    /// Return the typed parameter set for this deep link.
    pub fn params(&self) -> &P {
        &self.params
    }

    /// Return the optional x-callback-url metadata carried by this deep link.
    pub const fn x_callback(&self) -> &XCallbackParams {
        &self.x_callback
    }

    /// Attach x-callback-url metadata to this deep link.
    #[must_use]
    pub fn with_x_callback(mut self, x_callback: XCallbackParams) -> Self {
        self.x_callback = x_callback;
        self
    }

    /// Convert this typed deep link into a URL.
    ///
    /// # Panics
    ///
    /// Panics if the validated deep-link scheme and static intent cannot form a valid URL.
    pub fn to_url(&self) -> Url {
        let mut url = Url::parse(&format!("{}://{}", self.scheme.as_str(), I::NAME))
            .expect("invariant: deep-link scheme and intent form a valid URL");
        self.params.append_query_pairs(&mut url);
        self.x_callback.append_to_url(&mut url);
        url
    }
}

impl<I, P> FromStr for TypedDeepLink<I, P>
where
    I: DeepLinkIntent,
    P: DeepLinkParams,
{
    type Err = DeepLinkParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse_url(&Url::parse(value)?)
    }
}

impl<I, P> Display for TypedDeepLink<I, P>
where
    I: DeepLinkIntent,
    P: DeepLinkParams,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_url())
    }
}

impl<I, P> From<TypedDeepLink<I, P>> for Url
where
    I: DeepLinkIntent,
    P: DeepLinkParams,
{
    fn from(value: TypedDeepLink<I, P>) -> Self {
        value.to_url()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct TestIntent;

    impl DeepLinkIntent for TestIntent {
        const NAME: &'static str = "test";
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestParams {
        value: String,
    }

    impl DeepLinkParams for TestParams {
        fn parse(url: &Url) -> Result<Self, DeepLinkParseError> {
            let value = url
                .query_pairs()
                .find(|(key, _)| key == "value")
                .ok_or(DeepLinkParseError::MissingQueryParameter("value"))?
                .1
                .to_string();

            Ok(Self { value })
        }

        fn append_query_pairs(&self, url: &mut Url) {
            url.query_pairs_mut().append_pair("value", &self.value);
        }
    }

    type TestDeepLink = TypedDeepLink<TestIntent, TestParams>;

    #[test]
    fn creates_typed_deep_link_from_params() {
        let deep_link = TestDeepLink::new(
            DeepLinkScheme::PubkyAuth,
            TestParams {
                value: "hello".into(),
            },
        );

        assert_eq!(deep_link.scheme(), DeepLinkScheme::PubkyAuth);
        assert_eq!(deep_link.intent(), "test");
        assert_eq!(deep_link.params().value, "hello");
    }

    #[test]
    fn parses_typed_deep_link_from_url() {
        let url = Url::parse("pubkyauth://test?value=hello").unwrap();
        let deep_link = TestDeepLink::parse_url(&url).unwrap();

        assert_eq!(deep_link.params().value, "hello");
    }

    #[test]
    fn parses_typed_deep_link_from_str() {
        let deep_link: TestDeepLink = "pubkyring://test?value=hello".parse().unwrap();

        assert_eq!(deep_link.scheme(), DeepLinkScheme::PubkyRing);
        assert_eq!(deep_link.params().value, "hello");
    }

    #[test]
    fn converts_typed_deep_link_to_url() {
        let deep_link = TestDeepLink::new(
            DeepLinkScheme::PubkyAuth,
            TestParams {
                value: "hello world".into(),
            },
        );
        let url = deep_link.to_url();

        assert_eq!(url.scheme(), "pubkyauth");
        assert_eq!(url.host_str(), Some("test"));
        assert_eq!(TestDeepLink::parse_url(&url).unwrap(), deep_link);
    }

    #[test]
    fn displays_as_url() {
        let deep_link: TestDeepLink = "pubkyauth://test?value=hello".parse().unwrap();

        assert_eq!(deep_link.to_string(), deep_link.to_url().to_string());
    }

    #[test]
    fn converts_owned_typed_deep_link_into_url() {
        let deep_link: TestDeepLink = "pubkyauth://test?value=hello".parse().unwrap();
        let url: Url = deep_link.into();

        assert_eq!(url.as_str(), "pubkyauth://test?value=hello");
    }

    #[test]
    fn parses_and_serializes_x_callback_metadata() {
        let deep_link: TestDeepLink = "pubkyauth://test?value=hello&x-source=Bitkit%20Wallet&x-success=bitkit%3A%2F%2Fcallback%3Fnonce%3Dabc%26state%3Dready"
            .parse()
            .unwrap();

        assert_eq!(
            deep_link.x_callback(),
            &XCallbackParams {
                x_source: Some("Bitkit Wallet".into()),
                x_success: Some("bitkit://callback?nonce=abc&state=ready".into()),
                ..XCallbackParams::default()
            }
        );
        assert_eq!(
            deep_link.to_string(),
            "pubkyauth://test?value=hello&x-source=Bitkit%20Wallet&x-success=bitkit%3A%2F%2Fcallback%3Fnonce%3Dabc%26state%3Dready"
        );
    }

    #[test]
    fn attaches_x_callback_metadata_without_changing_params() {
        let deep_link = TestDeepLink::new(
            DeepLinkScheme::PubkyAuth,
            TestParams {
                value: "hello".into(),
            },
        )
        .with_x_callback(XCallbackParams {
            x_cancel: Some("bitkit://cancel".into()),
            ..XCallbackParams::default()
        });

        assert_eq!(deep_link.params().value, "hello");
        assert_eq!(
            deep_link.to_string(),
            "pubkyauth://test?value=hello&x-cancel=bitkit%3A%2F%2Fcancel"
        );
    }

    #[test]
    fn rejects_wrong_intent() {
        let error = "pubkyauth://other?value=hello"
            .parse::<TestDeepLink>()
            .unwrap_err();

        assert!(matches!(error, DeepLinkParseError::InvalidIntent("test")));
    }

    #[test]
    fn rejects_missing_required_param() {
        let error = "pubkyauth://test".parse::<TestDeepLink>().unwrap_err();

        assert!(matches!(
            error,
            DeepLinkParseError::MissingQueryParameter("value")
        ));
    }
}

use std::borrow::Cow;
use std::fmt::Debug;
use std::time::Duration;

use crate::{cross_log, errors::BuildError};

const DEFAULT_USER_AGENT: &str = concat!("pubky.org", "@", env!("CARGO_PKG_VERSION"),);

#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug, Clone, Default)]
struct NativeHttpConfig {
    request_timeout: Option<Duration>,
    pool_max_idle_per_host: Option<usize>,
}

#[derive(Debug, Clone)]
#[must_use]
/// Configures a [`PubkyHttpClient`] before construction.
///
/// Customize timeouts, user-agent, pkarr relays, and (WASM) testnet behavior.
/// Most code obtains this via [`PubkyHttpClient::builder()`], which simply returns
/// `PubkyHttpClientBuilder::default()`.
///
/// # Defaults
/// - Pkarr relays: [`crate::pkarr::DEFAULT_RELAYS`]
/// - HTTP request timeout (native only): reqwest default unless set via
///   [`Self::request_timeout`]
/// - User-agent: `pubky.org@<crate-version>` plus any [`Self::user_agent_extra`]
/// - Idle keep-alive connections per host (native only): reqwest default unless set via
///   [`Self::pool_max_idle_per_host`]
/// # Example
/// ```no_run
/// # #[cfg(not(target_arch = "wasm32"))]
/// # fn example() -> Result<(), pubky::BuildError> {
/// use std::time::Duration;
/// # use pubky::{PubkyHttpClient, PubkyHttpClientBuilder};
/// let client = PubkyHttpClient::builder()
///     .request_timeout(Duration::from_secs(10))
///     .user_agent_extra("myapp/1.2.3")
///     .pool_max_idle_per_host(10)
///     .build()?;
/// # Ok(()) }
/// ```
///
/// You can keep the default Pkarr relays or override them via the builder:
/// ```no_run
/// # use pubky::{PubkyHttpClient, PubkyHttpClientBuilder};
/// # fn main() -> Result<(), pubky::BuildError> {
/// // Start from defaults; you can also supply your own entirely.
/// let mut b = PubkyHttpClient::builder();
/// b.pkarr(|p| p.relays(&["https://pkarr.example.net/"]).expect("infallible"));
/// let _client = b.build()?;
/// # Ok(()) }
/// ```
#[derive(Default)]
pub struct PubkyHttpClientBuilder {
    pkarr: pkarr::ClientBuilder,

    /// Optional user-agent segment appended to the default UA for app-level telemetry.
    user_agent_extra: Option<String>,

    #[cfg(not(target_arch = "wasm32"))]
    native_http: NativeHttpConfig,

    /// The hostname to use for testnet URL transformations (WASM only).
    #[cfg(target_arch = "wasm32")]
    testnet_host: Option<String>,
}

impl PubkyHttpClientBuilder {
    #[cfg(test)]
    pub(crate) fn isolated_pkarr_test(&mut self) -> &mut Self {
        self.pkarr
            .no_default_network()
            .bootstrap(&["127.0.0.1:1"])
            .dht_report_policy(pkarr::dht::ReportPolicy::testnet());
        self
    }

    /// Configure this builder to talk to a **local Pubky testnet** on `localhost`.
    ///
    /// Concretely:
    /// - **DHT bootstrap** to the local testnet node at: `"localhost:6881"`
    /// - **PKARR relay** base URL: `"http://localhost:15411"`
    /// - **WASM builds** additionally remember the hostname when resolving `_pubky.<pk>` targets.
    ///
    /// # Examples
    /// ```
    /// use pubky::PubkyHttpClient;
    ///
    /// let client = PubkyHttpClient::builder()
    ///     .testnet()
    ///     .build()
    ///     .expect("testnet client");
    /// ```
    pub fn testnet(&mut self) -> &mut Self {
        self.testnet_with_host("localhost")
    }

    /// Configure this builder to talk to a **Pubky testnet** reachable at a custom host.
    ///
    /// Use this when your testnet stack isn’t on `localhost` (e.g. running in Docker,
    /// a remote VM, or LAN machine).
    ///
    /// Concretely:
    /// - DHT bootstrap peer: `"<host>:6881"` (native only)
    /// - PKARR relay base:   `"http://<host>:15411"`
    /// - WASM remembers `<host>` to adjust URL rewriting for the browser environment.
    ///
    /// # Examples
    /// ```
    /// use pubky::PubkyHttpClient;
    ///
    /// let client = PubkyHttpClient::builder()
    ///     .testnet_with_host("192.168.1.50") // or "host.docker.internal"
    ///     .build()
    ///     .expect("testnet client");
    /// ```
    ///
    /// # Notes
    /// - These ports come from `pubky_common::constants::testnet_ports::{ BOOTSTRAP, PKARR_RELAY }`.
    /// - Ensure your testnet exposes them from that host (and they’re reachable from where this code runs).
    ///
    /// # Panics
    /// If the testnet cannot because the given host leads to an invalid relay URL.
    #[cfg_attr(
        target_arch = "wasm32",
        allow(
            clippy::semicolon_outside_block,
            clippy::unnecessary_operation,
            clippy::semicolon_if_nothing_returned,
            reason = "WASM-only block preserves conditional assignment formatting"
        )
    )]
    pub fn testnet_with_host(&mut self, host: &str) -> &mut Self {
        cross_log!(info, "Configuring testnet builders for host {host}");
        #[cfg(not(target_arch = "wasm32"))]
        self.pkarr
            .bootstrap(&[format!(
                "{}:{}",
                host,
                pubky_common::constants::testnet_ports::BOOTSTRAP
            )])
            .dht_report_policy(pkarr::dht::ReportPolicy::testnet());

        self.pkarr
            .relays(&[format!(
                "http://{}:{}",
                host,
                pubky_common::constants::testnet_ports::PKARR_RELAY
            )])
            .expect("relays urls infallible");

        #[cfg(target_arch = "wasm32")]
        {
            self.testnet_host = Some(host.to_string());
        }

        self
    }

    /// Allows mutating the internal [`pkarr::ClientBuilder`] with a callback function.
    ///
    /// Use this to influence PKARR resolution inputs (relays, bootstrap nodes,
    /// timeouts, etc.) *before* building the client. There are no per-request
    /// resolution knobs; configuration is done up front.
    ///
    /// # Example
    /// ```
    /// # use pubky::{PubkyHttpClient, PubkyHttpClientBuilder};
    /// let client = PubkyHttpClient::builder()
    ///     .pkarr(|p| p
    ///         .relays(&["https://pkarr.example.net/"]).expect("infallible")
    ///         .bootstrap(&["dht.node.example:6881"])
    ///     )
    ///     .build()?;
    /// # Ok::<_, pubky::BuildError>(())
    /// ```
    pub fn pkarr<F>(&mut self, f: F) -> &mut Self
    where
        F: FnOnce(&mut pkarr::ClientBuilder) -> &mut pkarr::ClientBuilder,
    {
        f(&mut self.pkarr);

        self
    }

    /// Append an extra user-agent segment after the default `pubky.org@<version>`.
    /// Enables app-level telemetry
    /// Example: `.user_agent_extra("myapp/1.2.3")`
    pub fn user_agent_extra<S: Into<String>>(&mut self, extra: S) -> &mut Self {
        self.user_agent_extra = Some(extra.into());
        self
    }

    /// Build a [`PubkyHttpClient`].
    ///
    /// # Errors
    /// - [`crate::errors::BuildError::Pkarr`] if building the PKARR client fails.
    /// - [`crate::errors::BuildError::Http`] if constructing the HTTP client fails.
    ///
    /// # Examples
    /// ```
    /// # use pubky::PubkyHttpClient;
    /// let client = PubkyHttpClient::builder().build()?;
    /// # Ok::<_, pubky::BuildError>(())
    /// ```
    pub fn build(&self) -> Result<PubkyHttpClient, BuildError> {
        let pkarr = self.pkarr.build()?;

        // Compose user agent with optional extra part.
        let user_agent = self
            .user_agent_extra
            .as_deref()
            .map(str::trim)
            .filter(|extra| !extra.is_empty())
            .map_or_else(
                || Cow::Borrowed(DEFAULT_USER_AGENT),
                |extra| Cow::Owned(format!("{DEFAULT_USER_AGENT} {extra}")),
            );

        #[cfg(not(target_arch = "wasm32"))]
        cross_log!(
            info,
            "Building PubkyHttpClient (timeout: {:?}, user_agent: {}, pool_max_idle_per_host: {:?})",
            self.native_http.request_timeout,
            user_agent,
            self.native_http.pool_max_idle_per_host
        );
        #[cfg(target_arch = "wasm32")]
        cross_log!(
            info,
            "Building PubkyHttpClient (user_agent: {})",
            user_agent
        );

        #[cfg(not(target_arch = "wasm32"))]
        let mut http_builder =
            reqwest::ClientBuilder::from(pkarr.clone()).user_agent(user_agent.as_ref());

        #[cfg(target_arch = "wasm32")]
        let http_builder = reqwest::Client::builder().user_agent(user_agent.as_ref());

        #[cfg(not(target_arch = "wasm32"))]
        let mut icann_http_builder = reqwest::Client::builder()
            .user_agent(user_agent.as_ref())
            .tls_backend_preconfigured(icann_tls_config_without_revocation_check());

        // TODO: change this after Reqwest publish a release with timeout in wasm
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(timeout) = self.native_http.request_timeout {
            http_builder = http_builder.timeout(timeout);
            icann_http_builder = icann_http_builder.timeout(timeout);
        }

        #[cfg(not(target_arch = "wasm32"))]
        if let Some(max) = self.native_http.pool_max_idle_per_host {
            http_builder = http_builder.pool_max_idle_per_host(max);
            icann_http_builder = icann_http_builder.pool_max_idle_per_host(max);
        }

        Ok(PubkyHttpClient {
            pkarr,
            http: http_builder.build()?,

            #[cfg(not(target_arch = "wasm32"))]
            icann_http: icann_http_builder.build()?,

            #[cfg(not(target_arch = "wasm32"))]
            transport: super::http_targets::native::TransportResolver::new(),

            #[cfg(target_arch = "wasm32")]
            testnet_host: self.testnet_host.clone(),
        })
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl PubkyHttpClientBuilder {
    /// Set HTTP requests timeout.
    pub fn request_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.native_http.request_timeout = Some(timeout);
        self
    }

    /// Cap idle keep-alive connections per host. Set `0` to disable pooling.
    pub fn pool_max_idle_per_host(&mut self, max: usize) -> &mut Self {
        self.native_http.pool_max_idle_per_host = Some(max);
        self
    }
}

#[cfg(target_arch = "wasm32")]
impl PubkyHttpClientBuilder {
    /// Set HTTP requests timeout.
    ///
    /// # Deprecated
    /// This setter has never had any effect on WASM: reqwest uses the browser
    /// `fetch` backend and `build()` does not apply a global HTTP timeout.
    /// Use [`.pkarr()`](Self::pkarr) to configure pkarr/DHT request timeouts instead.
    #[deprecated(
        note = "HTTP request timeout is not supported on WASM and has never had any effect; use `.pkarr(|p| p.request_timeout(..))` for pkarr/DHT timeouts"
    )]
    pub fn request_timeout(&mut self, _timeout: Duration) -> &mut Self {
        self
    }
}

/// TLS config for the ICANN HTTP client: webpki/Mozilla roots, certificate revocation
/// checking disabled.
///
/// Revocation is disabled because reqwest's default verifier (rustls-platform-verifier)
/// hard-fails revocation on Android, where Let's Encrypt's sharded-CRL hierarchy makes it
/// falsely reject valid certificates ("invalid peer certificate: Revoked"). Only the ICANN
/// client uses this; the homeserver raw-public-key client keeps its pkarr-derived TLS.
#[cfg(not(target_arch = "wasm32"))]
fn icann_tls_config_without_revocation_check() -> rustls::ClientConfig {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut tls_config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("aws-lc-rs provides safe default protocol versions")
    .with_root_certificates(root_store)
    .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    tls_config
}

/// Transport client for Pubky homeserver APIs and generic HTTP, with PKARR-aware
/// URL handling.
///
/// `PubkyHttpClient` is the low-level engine the higher-level actors
/// (`PubkySession`, `PubkyStorage`, `Pkdns`, `PubkyGrantAuthFlow`) are built on. It owns:
/// - A pkarr DHT client (for resolving pkdns endpoints and publishing records).
/// - One or more reqwest HTTP clients (platform-specific).
///
/// ### What it does
/// - Detects pkarr public-key hosts and resolves them to concrete endpoints.
/// - Internally, uses a unified `cross_request(..)` that works the same on native rust and
///   WASM (WASM performs endpoint resolution & header injection; native is a thin wrapper).
///
/// ### What it *doesn’t* do
/// - It is **not** session/identity aware. No cookies, no per-user scoping.
///   For authenticated per-user flows use [`crate::PubkySession`].
///
/// ### When to use
/// - You want direct control over the `PubkyHttpClient` (power users, libs).
/// - You’re wiring custom flows/tests and don’t need the high-level ergonomics.
///
/// ### Construction
/// Use [`PubkyHttpClient::builder()`] to tweak timeouts, relays, or
/// user-agent; or pick sensible defaults via [`PubkyHttpClient::new()`]. A
/// [`PubkyHttpClient::testnet()`] helper configures a local test network.
///
/// ### Platform notes
/// - **Native (rust, not WASM target):**
///   - ICANN domains use standard X.509 TLS via the `icann_http` client.
///   - Pubky/PKDNS hosts (public-key hostnames or `_pubky.<pk>` domains) use **`PubkyTLS`**
///     (TLS with RFC 7250 Raw Public Keys), verifying the connection against the
///     target public key—no CA chain involved.
/// - **WASM:**
///   - All requests use the browser’s standard X.509 TLS stack.
///   - For Pubky/PKDNS hosts, private method `cross_request(..)` resolves the
///     endpoint via PKARR, rewrites the URL (including testnet/localhost mapping),
///     and may add a `pubky-host` header to convey the intended public-key host.
///
/// ### Examples
/// Basic construction. Works out of the box for mainline DHT pkarr endpoints.
/// ```
/// # use pubky::PubkyHttpClient;
/// # #[cfg(doctest)]
/// # return Ok::<_, pubky::BuildError>(());
/// let client = PubkyHttpClient::new()?;
/// # Ok::<_, pubky::BuildError>(())
/// ```
///
/// Fetching a standard ICANN URL or any URL with `request`:
/// ```no_run
/// # use pubky::{PubkyHttpClient, Result};
/// # use reqwest::Method;
/// # use url::Url;
/// # async fn run() -> Result<()> {
/// # #[cfg(doctest)]
/// # return Ok(());
/// let client = PubkyHttpClient::new()?;
/// let url = Url::parse("https://example.com")?;
/// let resp = client.request(Method::GET, &url)
///     .send().await?;
/// assert!(resp.status().is_success());
/// # Ok(()) }
/// ```
///
/// Note: `request(..)` is available on native targets. On WASM, use the high-level
/// actors (e.g., `Pubky`, `SessionStorage`, `PublicStorage`) or the JS bindings’
/// `client.fetch(..)` provided in `bindings/js`.
///
/// Fetching a Pubky resource via its transport URL:
/// ```no_run
/// # use pubky::{PubkyHttpClient, Result};
/// # use reqwest::Method;
/// # async fn run() -> Result<()> {
/// # #[cfg(doctest)]
/// # return Ok(());
/// let client = PubkyHttpClient::new()?;
/// // Pubky App profile of user Pubky https://pubky.app/profile/ihaqcthsdbk751sxctk849bdr7yz7a934qen5gmpcbwcur49i97y
/// let user = "ihaqcthsdbk751sxctk849bdr7yz7a934qen5gmpcbwcur49i97y";
/// let url = format!("https://_pubky.{user}/pub/pubky.app/profile.json");
/// let resp = client.request(Method::GET, &url).send().await?;
/// let info = resp.text().await?;
/// # Ok(()) }
/// ```
///
/// > Tip: For authenticated reads/writes, prefer `session.storage().get(...)`, which
/// > automatically scopes paths and attaches the right session cookie.
#[derive(Clone, Debug)]
pub struct PubkyHttpClient {
    pub(crate) http: reqwest::Client,
    pub(crate) pkarr: pkarr::Client,

    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) icann_http: reqwest::Client,

    /// Resolves and caches per-host transport decisions (`PubkyTLS` vs ICANN fallback).
    #[cfg(not(target_arch = "wasm32"))]
    pub(crate) transport: super::http_targets::native::TransportResolver,

    /// The hostname to use for testnet URL transformations (WASM only).
    #[cfg(target_arch = "wasm32")]
    pub(crate) testnet_host: Option<String>,
}

impl PubkyHttpClient {
    /// Creates a client configured for public mainline DHT and pkarr relays.
    ///
    /// # Errors
    /// - Returns [`BuildError`] if the underlying HTTP clients cannot be constructed or configured.
    pub fn new() -> Result<Self, BuildError> {
        cross_log!(
            info,
            "Constructing PubkyHttpClient with default configuration"
        );
        Self::builder().build()
    }

    /// Returns a builder to edit settings before creating [`PubkyHttpClient`].
    /// Prefer this when you need to control PKARR/DHT inputs (relays, bootstrap);
    /// resolution itself remains automatic during requests.
    pub fn builder() -> PubkyHttpClientBuilder {
        PubkyHttpClientBuilder::default()
    }

    /// Creates a [`PubkyHttpClient`] preconfigured to talk to a **locally running Pubky testnet**.
    ///
    /// # What this configures
    /// On **non wasm** targets (`not(target_arch = "wasm32")`):
    /// - **DHT bootstrap** to the local testnet node at: `"localhost:6881"`
    /// - **PKARR relay** base URL: `"http://localhost:15411"`
    ///
    /// On **WASM** targets:
    /// - Browser environments can’t dial UDP DHT; the builder is adjusted to use the
    ///   testnet HTTP endpoints suitable for the browser (no UDP bootstrap). PKARR HTTP
    ///   relay still points at `http://localhost:15411` unless you override it.
    ///
    /// # Requirements
    /// You must have `pubky-testnet` binary running locally (it provides a homeserver, a DHT bootstrap,
    /// and a PKARR relay on the ports above). For example:
    /// ```sh
    /// # From the pubky repo:
    /// cargo run -p pubky-testnet
    /// ```
    ///
    /// # Examples
    /// ```
    /// use pubky::PubkyHttpClient;
    ///
    /// let client = PubkyHttpClient::testnet()?;
    /// // Now all https://_pubky.<pubkey>/... requests resolve via the local testnet
    /// // DHT/PKARR, and hit the local homeserver.
    /// # Ok::<_, pubky::BuildError>(())
    /// ```
    ///
    /// # See also
    /// - [`PubkyHttpClientBuilder::testnet`] to tweak additional settings first.
    /// - [`PubkyHttpClientBuilder::testnet_with_host`] to target a non-`localhost` host.
    ///
    /// # Errors
    /// - Returns [`BuildError`] if the underlying HTTP clients cannot be constructed or configured for the testnet settings.
    pub fn testnet() -> Result<Self, BuildError> {
        cross_log!(
            info,
            "Constructing PubkyHttpClient configured for local testnet"
        );
        let mut builder = Self::builder();
        builder.testnet();
        builder.build()
    }

    // === Getters ===

    /// Returns a reference to the internal Pkarr Client.
    #[must_use]
    pub const fn pkarr(&self) -> &pkarr::Client {
        &self.pkarr
    }
}

#[cfg(test)]
mod test {
    use httpmock::MockServer;
    use reqwest::{Method, StatusCode};

    use super::*;

    #[tokio::test]
    async fn test_fetch() {
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method("GET").path("/health");
            then.status(200).body("ok");
        });

        let client = PubkyHttpClient::new().unwrap();
        let response = client
            .request(Method::GET, &server.url("/health"))
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        mock.assert();
    }
}

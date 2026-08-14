use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use super::homeserver_url;
use futures_util::StreamExt;
use tokio::net::TcpStream;

use crate::errors::RequestError;
use crate::{PubkyHttpClient, PublicKey, Result, cross_log};
use reqwest::{IntoUrl, Method, RequestBuilder};
use url::Url;

const TRANSPORT_CACHE_TTL: Duration = Duration::from_secs(60);
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

#[derive(Debug, Clone)]
pub(crate) enum ResolvedTransport {
    PubkyTls,
    Icann { domain: String, port: Option<u16> },
}

/// Resolves and caches per-host transport decisions (`PubkyTLS` vs ICANN).
///
/// Accepts a `&pkarr::Client` reference when resolution is needed — does not
/// own the pkarr client, which is shared across the SDK.
#[derive(Debug, Clone)]
pub(crate) struct TransportResolver {
    cache: Arc<RwLock<HashMap<String, (Instant, ResolvedTransport)>>>,
    guards: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
}

impl TransportResolver {
    pub(crate) fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            guards: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Look up the transport for `qname`, resolving via PKARR on cache miss.
    pub(crate) async fn resolve(&self, qname: &str, pkarr: &pkarr::Client) -> ResolvedTransport {
        if let Some(t) = self.cached(qname) {
            return t;
        }
        self.resolve_and_cache(qname, pkarr).await
    }

    /// Fast path: return a cached, non-expired transport decision.
    fn cached(&self, qname: &str) -> Option<ResolvedTransport> {
        let cache = self.cache.read().unwrap_or_else(PoisonError::into_inner);
        cache
            .get(qname)
            .filter(|(ts, _)| ts.elapsed() < TRANSPORT_CACHE_TTL)
            .map(|(_, t)| t.clone())
    }

    /// Slow path: acquire a per-qname guard, double-check the cache, resolve,
    /// and store the result.
    async fn resolve_and_cache(&self, qname: &str, pkarr: &pkarr::Client) -> ResolvedTransport {
        let guard = {
            let mut guards = self.guards.lock().unwrap_or_else(PoisonError::into_inner);
            Arc::clone(guards.entry(qname.to_string()).or_default())
        };
        let _lock = guard.lock().await;

        // Another task may have resolved while we waited for the guard.
        if let Some(t) = self.cached(qname) {
            return t;
        }

        let t = Self::resolve_from_pkarr(pkarr, qname).await;
        self.cache
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(qname.to_string(), (Instant::now(), t.clone()));
        t
    }

    /// Inspect PKARR endpoints and probe reachability to pick a transport.
    async fn resolve_from_pkarr(pkarr: &pkarr::Client, qname: &str) -> ResolvedTransport {
        let stream = pkarr.resolve_https_endpoints(qname);
        futures_util::pin_mut!(stream);

        let mut has_direct = false;
        let mut direct_addrs = Vec::new();
        let mut icann: Option<(String, Option<u16>)> = None;

        while let Some(ep) = stream.next().await {
            if let Some(domain) = ep.domain() {
                if icann.is_none() {
                    icann = Some((domain.to_string(), ep.port()));
                }
            } else {
                has_direct = true;
                direct_addrs.extend(ep.to_socket_addrs());
            }
        }

        let Some((domain, port)) = icann else {
            return ResolvedTransport::PubkyTls;
        };
        if !has_direct {
            return ResolvedTransport::Icann { domain, port };
        }

        // Both exist — probe direct endpoint reachability.
        if probe_reachable(&direct_addrs, PROBE_TIMEOUT).await {
            ResolvedTransport::PubkyTls
        } else {
            cross_log!(
                warn,
                "Direct endpoint unreachable for {qname}; ICANN fallback to {domain}"
            );
            ResolvedTransport::Icann { domain, port }
        }
    }
}

async fn probe_reachable(addrs: &[std::net::SocketAddr], timeout: Duration) -> bool {
    for addr in addrs {
        if let Ok(Ok(_)) = tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
            return true;
        }
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostKind {
    ResolvedPubky,
    Icann,
    Pubky,
}

fn classify_host(host: &str) -> HostKind {
    if let Some(pk_host) = host.strip_prefix("_pubky.") {
        if PublicKey::is_pubky_prefixed(pk_host) {
            return HostKind::Icann;
        }
        if PublicKey::try_from_z32(pk_host).is_ok() {
            return HostKind::ResolvedPubky;
        }
    } else if PublicKey::is_pubky_prefixed(host) || PublicKey::try_from_z32(host).is_err() {
        return HostKind::Icann;
    }
    HostKind::Pubky
}

impl PubkyHttpClient {
    /// Constructs a [`reqwest::RequestBuilder`] for the given HTTP `method` and `url`,
    /// routing through the client's unified request path.
    ///
    /// This method ensures that special Pubky and pkarr hosts are resolved according to
    /// platform-specific rules (native or WASM), including:
    /// - Detecting `_pubky.<public-key>` hosts and applying the correct TLS handling.
    /// - Routing standard ICANN domains through the `icann_http` client on native builds.
    /// - When both a direct (IP:PORT) and an ICANN (domain) endpoint exist, TCP-probing
    ///   the direct endpoint and falling back to ICANN if unreachable.
    ///
    /// Transport decisions are cached per host with a short TTL.
    ///
    /// Returns a [`Result`] containing the prepared `RequestBuilder`, or a URL/transport
    /// parsing error if the supplied `url` is invalid.
    pub(crate) async fn cross_request(
        &self,
        method: Method,
        mut url: Url,
    ) -> Result<RequestBuilder> {
        let Some(pk) = self.prepare_request(&mut url).await? else {
            return Ok(self.request(method, &url));
        };
        // Resolve the transport with the full host: for `_pubky.<pk>` hosts the
        // endpoints live under that qname, not the bare key apex. `pk` is only
        // the `pubky-host` header value.
        let qname = url.host_str().unwrap_or(&pk).to_string();
        let transport = self.transport.resolve(&qname, &self.pkarr).await;
        self.build_pubky_request(method, &url, &pk, &transport)
    }

    /// Native has no ambient browser cookie jar, so this is `cross_request`.
    pub(crate) async fn cross_request_anonymous(
        &self,
        method: Method,
        url: Url,
    ) -> Result<RequestBuilder> {
        self.cross_request(method, url).await
    }

    /// Route through `homeserver` while addressing `pubky_host`.
    pub(crate) async fn cross_request_via_homeserver(
        &self,
        method: Method,
        homeserver: &PublicKey,
        pubky_host: &PublicKey,
        path: &str,
    ) -> Result<RequestBuilder> {
        let url = homeserver_url(homeserver, path)?;
        let homeserver_z32 = homeserver.z32();
        let pubky_host_z32 = pubky_host.z32();
        let transport = self.transport.resolve(&homeserver_z32, &self.pkarr).await;

        match transport {
            ResolvedTransport::PubkyTls => Ok(self
                .http
                .request(method, url.as_str())
                .header("pubky-host", pubky_host_z32)),
            ResolvedTransport::Icann { .. } => {
                self.build_pubky_request(method, &url, &pubky_host_z32, &transport)
            }
        }
    }

    /// Build a [`RequestBuilder`] for a resolved pubky host transport.
    fn build_pubky_request(
        &self,
        method: Method,
        url: &Url,
        pk: &str,
        transport: &ResolvedTransport,
    ) -> Result<RequestBuilder> {
        match transport {
            ResolvedTransport::PubkyTls => Ok(self.http.request(method, url.as_str())),
            ResolvedTransport::Icann { domain, port } => {
                let mut icann_url = url.clone();
                icann_url.set_host(Some(domain))?;
                if let Some(p) = port {
                    icann_url
                        .set_port(Some(*p))
                        .map_err(|_err| url::ParseError::InvalidPort)?;
                }
                cross_log!(debug, "ICANN fallback for {pk} via {domain}");
                Ok(self
                    .icann_http
                    .request(method, icann_url.as_str())
                    .header("pubky-host", pk))
            }
        }
    }

    /// Detect pubky hosts and return the z32 public key when applicable.
    ///
    /// Native builds do not rewrite URLs; we only detect pubky hosts and return the
    /// `pubky-host` value when applicable.
    ///
    /// # Errors
    /// Returns [`RequestError::Validation`] if the host uses a `pubky` prefix.
    #[allow(
        clippy::unused_async,
        reason = "keep async signature aligned with WASM build"
    )]
    pub async fn prepare_request(&self, url: &mut Url) -> Result<Option<String>> {
        let host = url.host_str().unwrap_or("");

        if let Some(stripped) = host.strip_prefix("_pubky.") {
            if PublicKey::is_pubky_prefixed(stripped) {
                return Err(RequestError::Validation {
                    message: "pubky prefix is not allowed in transport hosts; use raw z32"
                        .to_string(),
                }
                .into());
            }
            if PublicKey::try_from_z32(stripped).is_ok() {
                return Ok(Some(stripped.to_string()));
            }
        } else {
            if PublicKey::is_pubky_prefixed(host) {
                return Err(RequestError::Validation {
                    message: "pubky prefix is not allowed in transport hosts; use raw z32"
                        .to_string(),
                }
                .into());
            }
            if PublicKey::try_from_z32(host).is_ok() {
                return Ok(Some(host.to_string()));
            }
        }

        Ok(None)
    }

    /// Start building a `Request` with the `Method` and `Url` (native-only).
    ///
    /// Returns a `RequestBuilder`, which will allow setting headers and
    /// the request body before sending.
    ///
    /// Differs from [`reqwest::Client::request`], in that it can make requests to:
    /// 1. HTTPS URLs with a [`crate::PublicKey`] as top-level domain, by resolving
    ///    corresponding endpoints, and verifying TLS certificates accordingly.
    ///    (example: `https://o4dksfbqk85ogzdb5osziw6befigbuxmuxkuxq8434q89uj56uyy`)
    /// 2. `_pubky.<public-key>` URLs like `https://_pubky.o4dksfbqk85ogzdb5osziw6befigbuxmuxkuxq8434q89uj56uyy`
    ///
    /// # Errors
    ///
    /// This method fails whenever the supplied `Url` cannot be parsed.
    pub fn request<U: IntoUrl>(&self, method: Method, url: &U) -> RequestBuilder {
        let url_str = url.as_str();

        let host = Url::parse(url_str)
            .ok()
            .and_then(|url| url.host_str().map(str::to_owned));

        if let Some(ref host) = host {
            match classify_host(host) {
                HostKind::ResolvedPubky => {
                    cross_log!(debug, "PubkyTLS request for resolved _pubky host {}", host);
                    return self.http.request(method, url_str);
                }
                HostKind::Icann => {
                    cross_log!(debug, "Standard TLS request for ICANN host {}", host);
                    return self.icann_http.request(method, url_str);
                }
                HostKind::Pubky => {
                    cross_log!(debug, "PubkyTLS request for pubky host {}", host);
                }
            }
        }

        self.http.request(method, url_str)
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::*;
    use pkarr::dns::rdata::SVCB;
    use pkarr::{Cache, InMemoryCache, Keypair, SignedPacket};

    #[test]
    fn classify_hosts() {
        assert_eq!(classify_host("example.com"), HostKind::Icann);
        let z32 = "o4dksfbqk85ogzdb5osziw6befigbuxmuxkuxq8434q89uj56uyy";
        assert_eq!(
            classify_host(&format!("_pubky.{z32}")),
            HostKind::ResolvedPubky
        );
        assert_eq!(classify_host(z32), HostKind::Pubky);
    }

    #[tokio::test]
    async fn probe_unreachable_returns_false() {
        let addr = "192.0.2.1:1".parse().unwrap(); // TEST-NET-1, RFC 5737
        assert!(!probe_reachable(&[addr], Duration::from_millis(100)).await);
    }

    /// Helper: build a pkarr client with a pre-cached signed packet (no real network).
    fn pkarr_with_packet(keypair: &Keypair, packet: &SignedPacket) -> pkarr::Client {
        let cache = Arc::new(InMemoryCache::new(NonZeroUsize::MIN));
        let mut builder = PubkyHttpClient::builder();
        builder
            .isolated_pkarr_test()
            .pkarr(|b| b.cache(cache.clone()));
        let client = builder.build().unwrap();
        let cache_key: pkarr::CacheKey = keypair.public_key().into();
        cache.put(&cache_key, packet);
        client.pkarr
    }

    #[test]
    fn build_pubky_request_icann_rewrites_url_and_sets_header() {
        let client = PubkyHttpClient::builder()
            .isolated_pkarr_test()
            .build()
            .unwrap();
        let z32 = "o4dksfbqk85ogzdb5osziw6befigbuxmuxkuxq8434q89uj56uyy";
        let url = Url::parse(&format!("https://{z32}/pub/app/file.txt")).unwrap();
        let transport = ResolvedTransport::Icann {
            domain: "example.com".to_string(),
            port: Some(8443),
        };

        let req = client
            .build_pubky_request(Method::GET, &url, z32, &transport)
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(req.url().host_str(), Some("example.com"));
        assert_eq!(req.url().port(), Some(8443));
        assert_eq!(req.url().path(), "/pub/app/file.txt");
        assert_eq!(req.headers().get("pubky-host").unwrap(), z32);
    }

    #[tokio::test]
    async fn resolve_transport_direct_only() {
        let kp = Keypair::random();
        let mut svcb = SVCB::new(1, ".".try_into().unwrap());
        svcb.set_port(6881);
        let packet = SignedPacket::builder()
            .https(".".try_into().unwrap(), svcb, 3600)
            .address(".".try_into().unwrap(), "192.0.2.1".parse().unwrap(), 3600)
            .sign(&kp)
            .unwrap();
        let pkarr = pkarr_with_packet(&kp, &packet);

        let t = TransportResolver::resolve_from_pkarr(&pkarr, &kp.public_key().to_string()).await;
        assert!(matches!(t, ResolvedTransport::PubkyTls));
    }

    #[tokio::test]
    async fn resolve_transport_icann_only() {
        let kp = Keypair::random();
        let svcb = SVCB::new(1, "example.com".try_into().unwrap());
        let packet = SignedPacket::builder()
            .https(".".try_into().unwrap(), svcb, 3600)
            .sign(&kp)
            .unwrap();
        let pkarr = pkarr_with_packet(&kp, &packet);

        let t = TransportResolver::resolve_from_pkarr(&pkarr, &kp.public_key().to_string()).await;
        assert!(matches!(t, ResolvedTransport::Icann { .. }));
        if let ResolvedTransport::Icann { domain, .. } = t {
            assert_eq!(domain, "example.com");
        }
    }

    /// Regression test: requests to `https://_pubky.<user>/...` must apply the
    /// ICANN fallback. The user's endpoints are published under the
    /// `_pubky.<user>` qname (an alias to the homeserver key), so the
    /// transport must be resolved with the full host, not the bare key.
    #[tokio::test]
    async fn cross_request_pubky_host_falls_back_to_icann_when_direct_unreachable() {
        // Homeserver apex: unreachable direct endpoint + reachable ICANN domain.
        let homeserver = Keypair::random();
        let mut direct = SVCB::new(1, ".".try_into().unwrap());
        direct.set_port(6287);
        let icann = SVCB::new(10, "example.com".try_into().unwrap());
        let homeserver_packet = SignedPacket::builder()
            .https(".".try_into().unwrap(), direct, 3600)
            .https(".".try_into().unwrap(), icann, 3600)
            .address(".".try_into().unwrap(), "192.0.2.1".parse().unwrap(), 3600)
            .sign(&homeserver)
            .unwrap();

        // User `_pubky` record aliasing to the homeserver key, mirroring
        // `Pkdns::build_homeserver_packet`.
        let user = Keypair::random();
        let homeserver_z32 = homeserver.public_key().to_string();
        let alias = SVCB::new(0, homeserver_z32.as_str().try_into().unwrap());
        let user_packet = SignedPacket::builder()
            .https("_pubky".try_into().unwrap(), alias, 3600)
            .sign(&user)
            .unwrap();

        let cache = Arc::new(InMemoryCache::new(NonZeroUsize::new(2).unwrap()));
        let mut builder = PubkyHttpClient::builder();
        builder
            .isolated_pkarr_test()
            .pkarr(|b| b.cache(cache.clone()));
        let client = builder.build().unwrap();
        cache.put(&homeserver.public_key().into(), &homeserver_packet);
        cache.put(&user.public_key().into(), &user_packet);

        let user_z32 = user.public_key().to_string();
        let url = Url::parse(&format!("https://_pubky.{user_z32}/session")).unwrap();
        let req = client
            .cross_request(Method::POST, url)
            .await
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(
            req.url().host_str(),
            Some("example.com"),
            "expected ICANN fallback for _pubky host, got {}",
            req.url()
        );
        assert_eq!(req.headers().get("pubky-host").unwrap(), &user_z32);
    }

    #[tokio::test]
    async fn cross_request_via_homeserver_routes_to_homeserver_with_user_pubky_host() {
        let homeserver = Keypair::random();
        let user = Keypair::random();
        let icann = SVCB::new(10, "example.com".try_into().unwrap());
        let homeserver_packet = SignedPacket::builder()
            .https(".".try_into().unwrap(), icann, 3600)
            .sign(&homeserver)
            .unwrap();

        let cache = Arc::new(InMemoryCache::new(NonZeroUsize::MIN));
        let mut builder = PubkyHttpClient::builder();
        builder
            .isolated_pkarr_test()
            .pkarr(|b| b.cache(cache.clone()));
        let client = builder.build().unwrap();
        cache.put(&homeserver.public_key().into(), &homeserver_packet);
        let homeserver_pk = PublicKey::try_from_z32(&homeserver.public_key().to_string()).unwrap();
        let user_pk = PublicKey::try_from_z32(&user.public_key().to_string()).unwrap();

        let req = client
            .cross_request_via_homeserver(Method::POST, &homeserver_pk, &user_pk, "/session")
            .await
            .unwrap()
            .build()
            .unwrap();

        assert_eq!(req.url().host_str(), Some("example.com"));
        assert_eq!(req.url().path(), "/session");
        assert_eq!(req.headers().get("pubky-host").unwrap(), &user_pk.z32());
    }

    #[tokio::test]
    async fn resolve_transport_both_unreachable_direct_falls_back() {
        let kp = Keypair::random();
        let mut direct = SVCB::new(1, ".".try_into().unwrap());
        direct.set_port(6881);
        let icann = SVCB::new(10, "example.com".try_into().unwrap());
        let packet = SignedPacket::builder()
            .https(".".try_into().unwrap(), direct, 3600)
            .https(".".try_into().unwrap(), icann, 3600)
            .address(".".try_into().unwrap(), "192.0.2.1".parse().unwrap(), 3600)
            .sign(&kp)
            .unwrap();
        let pkarr = pkarr_with_packet(&kp, &packet);

        let t = TransportResolver::resolve_from_pkarr(&pkarr, &kp.public_key().to_string()).await;
        assert!(
            matches!(t, ResolvedTransport::Icann { ref domain, .. } if domain == "example.com"),
            "expected ICANN fallback, got {t:?}"
        );
    }
}

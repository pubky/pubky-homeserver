// js/src/constructor.rs
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tsify::{Ts, Tsify};
use wasm_bindgen::prelude::*;

use crate::js_error::{JsResult, PubkyError, PubkyErrorName};

// ------------------------------------------------------------------------------------------------
// JS style config objects for the client.
// ------------------------------------------------------------------------------------------------

/// Pkarr Config
#[derive(Tsify, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PkarrConfig {
    /// The list of relays to access the DHT with.
    #[tsify(optional)]
    pub(crate) relays: Option<Vec<String>>,
    /// The timeout for relay HTTP requests in milliseconds.
    /// Default is 5000ms.
    #[tsify(optional)]
    pub(crate) request_timeout: Option<u64>,
}

/// Pubky Client Config
#[derive(Tsify, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PubkyClientConfig {
    /// Configuration on how to access pkarr packets on the mainline DHT.
    #[tsify(optional)]
    pub(crate) pkarr: Option<PkarrConfig>,
    /// Maximum raw HTTP error-body bytes to capture. Defaults to 4096; zero skips the body.
    /// UTF-8 decoding can produce up to three times as many bytes of text, plus the
    /// truncation marker. This does not cap final message size or total memory use.
    #[tsify(optional)]
    pub(crate) max_error_body_bytes: Option<usize>,
    /// Total deadline for each HTTP request in milliseconds, from sending until the
    /// response body finishes. Also ends event streams and auth relay long-polls.
    /// In Node it may not end a body that stalls after the response arrives.
    /// No deadline by default. Pkarr lookups use `pkarr.requestTimeout` instead.
    #[tsify(optional)]
    pub(crate) request_timeout: Option<u64>,
}

/// Low-level HTTP bridge used by the Pubky facade and actors.
///
/// - Supports `http(s)://` URLs targeting Pubky or ICANN hosts.
/// - In browsers/undici, passes `credentials: "include"` to send cookies.
#[wasm_bindgen]
pub struct Client(pub(crate) pubky::PubkyHttpClient);

impl Default for Client {
    fn default() -> Self {
        Self::new(None).expect("default constructor should be infallible")
    }
}

#[wasm_bindgen]
impl Client {
    /// Create a Pubky HTTP client.
    ///
    /// @param {PubkyClientConfig} [config]
    /// Optional request deadline, error-body limit and PKARR overrides:
    /// `{ requestTimeout?: number, maxErrorBodyBytes?: number, pkarr?: { relays?: string[], requestTimeout?: number } }`.
    /// `requestTimeout` bounds each SDK HTTP request in milliseconds (no deadline by default),
    /// including event streams and auth relay long-polls; requests that exceed it reject with
    /// `RequestError` reason `Timeout`. `Client.fetch` does not apply it; pass a `signal` instead.
    /// In Node it may not end a body that stalls after the response arrives (see the README).
    /// `pkarr.requestTimeout` only bounds pkarr relay lookups.
    ///
    /// @returns {Client}
    /// A configured low-level client. Prefer `new Pubky().client` unless you
    /// need custom relays, timeouts or error-body limits.
    ///
    /// @throws {InvalidInput}
    /// If a relay URL is invalid, the error-body limit is not an integer in 0..=4294967295,
    /// or `requestTimeout` is not an integer in 1..=2147483647.
    ///
    /// @example
    /// const client = new Client({
    ///   requestTimeout: 30000,
    ///   maxErrorBodyBytes: 1024,
    ///   pkarr: { relays: ["https://relay1/","https://relay2/"], requestTimeout: 8000 }
    /// });
    /// const pubky = Pubky.withClient(client);
    #[wasm_bindgen(constructor)]
    pub fn new(config_opt: Option<Ts<PubkyClientConfig>>) -> JsResult<Self> {
        // A JSON roundtrip would turn NaN/Infinity into null and silently use defaults.
        let config_opt = config_opt
            .map(|config| serde_wasm_bindgen::from_value::<PubkyClientConfig>(config.js_value()))
            .transpose()
            .map_err(|error| PubkyError::new(PubkyErrorName::InvalidInput, error))?;
        let mut builder = pubky::PubkyHttpClient::builder();

        if let Some(config) = config_opt {
            if let Some(limit) = config.max_error_body_bytes {
                builder.max_error_body_bytes(limit);
            }
            if let Some(timeout_ms) = config.request_timeout {
                // Zero would abort every request; `build()` rejects values above the maximum.
                if timeout_ms == 0 {
                    return Err(PubkyError::new(
                        PubkyErrorName::InvalidInput,
                        "requestTimeout must be at least 1 ms",
                    ));
                }
                builder.request_timeout(Duration::from_millis(timeout_ms));
            }
            if let Some(pkarr) = config.pkarr {
                // Relays
                if let Some(relays) = pkarr.relays {
                    let mut relay_set_error: Option<String> = None;
                    builder.pkarr(|p| {
                        p.no_relays();
                        if let Err(e) = p.relays(&relays) {
                            relay_set_error = Some(e.to_string());
                        }
                        p
                    });
                    if let Some(msg) = relay_set_error {
                        return Err(PubkyError::new(PubkyErrorName::InvalidInput, msg));
                    }
                }
                // Timeout
                if let Some(timeout_ms) = pkarr.request_timeout {
                    builder.pkarr(|p| {
                        p.relay_request_timeout(Duration::from_millis(timeout_ms));
                        p
                    });
                }
            }
        }

        let client = builder.build()?;
        log::debug!("Client created: {:?}", client);

        Ok(Self(client))
    }

    /// Create a client wired for **local testnet**.
    ///
    /// Configures PKARR relays for the testnet and remembers the hostname for WASM `_pubky` mapping.
    ///
    /// @param {string} [host="localhost"]
    /// Testnet hostname or IP.
    ///
    /// @returns {Client}
    /// A client ready to talk to your local testnet.
    ///
    /// @example
    /// const client = Client.testnet();           // localhost
    /// const pubky  = Pubky.withClient(client);
    ///
    /// @example
    /// const client = Client.testnet("docker0");  // custom host
    #[wasm_bindgen]
    pub fn testnet(host: Option<String>) -> JsResult<Self> {
        let hostname = host.unwrap_or_else(|| "localhost".to_string());

        let mut builder = pubky::PubkyHttpClient::builder();
        builder.testnet_with_host(&hostname);

        let client = builder.build()?;
        log::debug!("Client created: {:?}", client);

        Ok(Self(client))
    }
}

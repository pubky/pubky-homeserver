// js/src/constructor.rs
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tsify::{Ts, Tsify};
use wasm_bindgen::prelude::*;

use crate::js_error::{JsResult, PubkyError, PubkyErrorName, deserialize_ts};

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
    /// The timeout for DHT requests in milliseconds.
    /// Default is 2000ms.
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
    // NOTE: user_max_record_age belonged to the old client — removed here.
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
    /// Optional transport overrides:
    /// `{ pkarr?: { relays?: string[], request_timeout?: number } }`.
    ///
    /// @returns {Client}
    /// A configured low-level client. Prefer `new Pubky().client` unless you
    /// need custom relays/timeouts.
    ///
    /// @throws {InvalidInput}
    /// If any PKARR relay URL is invalid.
    ///
    /// @example
    /// const client = new Client({
    ///   pkarr: { relays: ["https://relay1/","https://relay2/"], request_timeout: 8000 }
    /// });
    /// const pubky = Pubky.withClient(client);
    #[wasm_bindgen(constructor)]
    pub fn new(config_opt: Option<Ts<PubkyClientConfig>>) -> JsResult<Self> {
        let config_opt = config_opt.as_ref().map(deserialize_ts).transpose()?;
        let mut builder = pubky::PubkyHttpClient::builder();

        if let Some(config) = config_opt
            && let Some(pkarr) = config.pkarr
        {
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
                    p.request_timeout(Duration::from_millis(timeout_ms));
                    p
                });
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

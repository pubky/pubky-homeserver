//! Constants used across Pubky.

/// [Reserved param keys](https://www.rfc-editor.org/rfc/rfc9460#name-initial-contents) for HTTPS Resource Records
pub mod reserved_param_keys {
    /// HTTPS (RFC 9460) record's private param key, used to inform browsers
    /// about the HTTP port to use when the domain is localhost.
    pub const HTTP_PORT: u16 = 65280;
}

/// Pubky storage namespace roots.
pub mod storage {
    /// Storage root for private data.
    pub const PRIVATE_ROOT: &str = "/priv/";

    /// Storage root for public, world-readable data.
    pub const PUBLIC_ROOT: &str = "/pub/";
}

/// Local test network's hardcoded port numbers for local development.
pub mod testnet_ports {
    /// The local test network's hardcoded DHT bootstrapping node's port number.
    pub const BOOTSTRAP: u16 = 6881;
    /// The local test network's hardcoded Pkarr Relay port number.
    pub const PKARR_RELAY: u16 = 15411;
    /// The local test network's hardcoded HTTP Relay port number.
    pub const HTTP_RELAY: u16 = 15412;
    /// The local test network's hardcoded Homeserver ICANN HTTP port number.
    pub const HOMESERVER_ICANN_HTTP: u16 = 6286;
    /// The local test network's hardcoded Homeserver Pubky HTTPS port number.
    pub const HOMESERVER_PUBKY_HTTPS: u16 = 6287;
    /// The local test network's hardcoded Homeserver admin port number.
    pub const HOMESERVER_ADMIN: u16 = 6288;
}

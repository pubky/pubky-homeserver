# Pubky Homeserver

A homeserver for Pubky. Stores and serves user data via HTTP APIs with public-key authentication.

For standalone deployment, see the [install guide](../docs/INSTALL.md).

## Development

Run the homeserver directly from the source tree:

```bash
cargo run -p pubky-homeserver -- --data-dir ~/.pubky
```

See [config.sample.toml](config.sample.toml) for all configuration options.

### Client compatibility

When an SDK change requires homeserver behavior that older versions do not
support, such as a new endpoint, add a stable feature identifier to the client
`GET /info` response. SDKs must check that identifier before using the new
behavior.

## API Specifications

- [Client API](openapi-client.yml) — user authentication, tenant storage, and event feeds.
- [Admin API](openapi-admin.yml) — homeserver administration and WebDAV operations.

## Architecture

- [PKARR republishing](../docs/REPUBLISHING.md) — cache-first resolution, network fallback, and retry behavior.

## Library Usage

Use the homeserver as a library in other crates or for testing.

```toml
[dependencies]
pubky-homeserver = "0.x"  # replace with the latest version
```

`HomeserverApp` starts the full server stack (client server, admin server, metrics server, DHT republishers):

```rust
use pubky_homeserver::HomeserverApp;
use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let app = HomeserverApp::start_with_persistent_data_dir_path(
        PathBuf::from("~/.pubky")
    ).await?;

    println!("Homeserver HTTP: {}", app.icann_http_url());
    println!("Homeserver Pubky TLS: {}", app.pubky_url());

    if let Some(admin) = app.admin_server() {
        println!("Admin server: http://{}", admin.listen_socket());
    }

    tokio::signal::ctrl_c().await?;
    Ok(())
}
```

For testing, use `MockDataDir` to create a temporary directory that is cleaned up on drop. Enable the `testing` feature:

```toml
[dev-dependencies]
pubky-homeserver = { version = "0.x", features = ["testing"] }
```

```rust,ignore
use pubky_homeserver::{HomeserverApp, MockDataDir, ConfigToml};

let config = ConfigToml::default_test_config();
let mock_dir = MockDataDir::new(config, None).unwrap();
let app = HomeserverApp::start_with_mock_data_dir(mock_dir).await.unwrap();
```

### Binary

See [Install and Run Pubky Homeserver](../docs/INSTALL.md) for full setup instructions.

```bash
pubky-homeserver --data-dir ~/.pubky
```

## Storage

`/pub/` is public; `/priv/` requires an authenticated session and a covering
capability. See [Private Storage](../docs/PRIVATE_STORAGE.md) for the full contract.

## Caching and Proxies

Private responses are sent with `Cache-Control: no-store` so shared caches
never store them:

- `/storage/{user_z32}/priv/...` responses vary on `Authorization` and
  `Cookie`. The owner is part of the URL, so `pubky-host` is not part of the
  cache key.
- Deprecated `/priv/...` responses and `/events-stream` vary on
  `pubky-host`, `Authorization`, and `Cookie`.

Public files remain cacheable. `/storage/{user_z32}/pub/...` responses do not
vary on `pubky-host`; deprecated `/pub/...` responses still do.

Note: CORS preflight `OPTIONS` is
handled upstream by the CORS layer and carries no private body.

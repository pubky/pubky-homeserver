# Pubky Testnet

A local test network for developing Pubky Core or applications depending on it.

## Quick start

Start Postgres if you don't already have one running:

```bash
docker run --name pubky-postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -p 127.0.0.1:5432:5432 \
  -d postgres:18
```

> For more Postgres setup options see the [Install Guide — Set Up PostgreSQL](../docs/INSTALL.md#set-up-postgresql).

Run a local testnet with persistent state:

```bash
TEST_PUBKY_CONNECTION_STRING='postgres://postgres:postgres@localhost:5432/postgres' \
  cargo run -p pubky-testnet -- persist ./my-testnet-data
```

The data directory is auto-initialized on first run with a `config.toml` and server keypair. On subsequent runs, the existing state is picked up and the homeserver keeps the same identity.

The `TEST_PUBKY_CONNECTION_STRING` environment variable is read on every startup and overrides the `database_url` in the on-disk config.

To seed a custom homeserver config on first run (errors if `config.toml` already exists):

```bash
TEST_PUBKY_CONNECTION_STRING='postgres://postgres:postgres@localhost:5432/postgres' \
  cargo run -p pubky-testnet -- --homeserver-config my-config.toml persist ./my-testnet-data
```

If you don't need persistent state, omit the `persist` subcommand and add `?pubky-test=true` to the connection string. The database is auto-created on startup and cleaned up on shutdown:

```bash
TEST_PUBKY_CONNECTION_STRING='postgres://postgres:postgres@localhost:5432/postgres?pubky-test=true' \
  cargo run -p pubky-testnet
```

### Ports and addresses

| Component | Port |
|-----------|------|
| DHT bootstrap node | `6881` |
| Pkarr relay | `15411` |
| HTTP relay | `15412` |
| Homeserver ICANN HTTP | `6286` |
| Homeserver Pubky HTTPS | `6287` |
| Homeserver admin | `6288` |

Homeserver address: `8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo`

The CLI uses [`StaticTestnet`] under the hood — see the type's rustdoc for programmatic use.

## Writing tests (EphemeralTestnet)

For automated Rust tests, use [`EphemeralTestnet`]. Each instance gets its own isolated DHT and homeserver with random ports, so tests run in parallel without conflicts.

```rust,no_run
use pubky_testnet::EphemeralTestnet;

#[tokio::test]
#[pubky_testnet::test] // Cleans up ephemeral Postgres databases after the test
async fn my_test() {
    // Note: both attributes are required — #[tokio::test] provides the async
    // runtime, #[pubky_testnet::test] registers a cleanup hook for test DBs.
    let testnet = EphemeralTestnet::builder().build().await.unwrap();

    // Create a Pubky Http Client from the testnet.
    let client = testnet.client().unwrap();

    // Use the homeserver
    let homeserver = testnet.homeserver_app();
}
```

### Postgres for tests

You need a running PostgreSQL instance (see [Quick start](#quick-start) for a Docker one-liner). By default, `EphemeralTestnet` reads the `TEST_PUBKY_CONNECTION_STRING` environment variable. The `?pubky-test=true` parameter tells the homeserver to create an ephemeral `pubky_test_*` database. The `#[pubky_testnet::test]` macro ensures the database is cleaned up after the test completes or panics.

```bash
TEST_PUBKY_CONNECTION_STRING='postgres://postgres:postgres@localhost:5432/postgres?pubky-test=true' \
  cargo test -p my-crate
```

You can also pass the connection string programmatically:

```rust,no_run
use pubky_testnet::{EphemeralTestnet, pubky_homeserver::ConnectionString};

#[tokio::test]
#[pubky_testnet::test]
async fn my_test() {
    let connection_string = ConnectionString::new(
        "postgres://postgres:postgres@localhost:5432/postgres?pubky-test=true"
    ).unwrap();

    let testnet = EphemeralTestnet::builder()
        .postgres(connection_string)
        .build()
        .await
        .unwrap();
}
```

### Docker Postgres

To avoid managing Postgres yourself, enable the `docker-postgres` feature. This uses [testcontainers](https://docs.rs/testcontainers) to run PostgreSQL in a Docker container that is automatically cleaned up on drop and on Ctrl+C/SIGTERM. Docker must be running on the host.

```toml
[dev-dependencies]
pubky-testnet = { version = "<version>", features = ["docker-postgres"] }
```

```rust,no_run
# #[cfg(not(feature = "docker-postgres"))]
# fn main() {}
# #[cfg(feature = "docker-postgres")]
use pubky_testnet::EphemeralTestnet;

# #[cfg(feature = "docker-postgres")]
#[tokio::main]
async fn main() {
    let testnet = EphemeralTestnet::builder()
        .with_docker_postgres()
        .build()
        .await
        .unwrap();
}
```

Each call to `.with_docker_postgres()` starts a **separate** container. To share **one** container across all tests, use `DockerPostgres::shared()`:

```rust
# #[cfg(feature = "docker-postgres")]
# mod docker_postgres_example {
use pubky_testnet::EphemeralTestnet;
use pubky_testnet::docker_postgres::DockerPostgres;

#[tokio::test]
async fn test_one() {
    let pg = DockerPostgres::shared().await;
    let testnet = EphemeralTestnet::builder()
        .postgres(pg.connection_string().unwrap())
        .build()
        .await
        .unwrap();
    // ... test code
}

#[tokio::test]
async fn test_two() {
    let pg = DockerPostgres::shared().await;
    let testnet = EphemeralTestnet::builder()
        .postgres(pg.connection_string().unwrap())
        .build()
        .await
        .unwrap();
    // ... test code
}
# }
```

Each testnet still gets its own ephemeral database within the shared PostgreSQL instance, so tests remain isolated.

### Custom configuration

```rust,no_run
use pubky_testnet::{EphemeralTestnet, pubky_homeserver::ConfigToml, pubky::Keypair};

#[tokio::main]
async fn main() {
    // Enable admin server for tests that need it
    let testnet = EphemeralTestnet::builder()
        .config(ConfigToml::default_test_config())
        .build()
        .await
        .unwrap();

    // Or use a custom keypair
    let testnet = EphemeralTestnet::builder()
        .keypair(Keypair::random())
        .build()
        .await
        .unwrap();

    // Enable HTTP relay for tests that need it
    let testnet = EphemeralTestnet::builder()
        .with_http_relay()
        .build()
        .await
        .unwrap();
    let http_relay = testnet.http_relay();
}
```

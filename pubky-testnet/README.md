# Pubky Testnet

A local test network for developing Pubky Core or applications depending on it.

Two testnet types are provided:

| Type | Ports | Storage | Use case |
|------|-------|---------|----------|
| [`EphemeralTestnet`] | Random | In-memory | Automated tests (`#[tokio::test]`) - parallel-safe, no port conflicts |
| [`StaticTestnet`] | Fixed, well-known | In-memory or persistent | Interactive / CLI use - browser tests, mobile apps, manual debugging |

## Prerequisites

All testnet modes require a PostgreSQL database. You can either:

- **Use Docker Postgres** (recommended for tests) — enable the `docker-postgres` feature, no external setup needed.
- **Run your own Postgres** - set the `TEST_PUBKY_CONNECTION_STRING` environment variable.

```bash
# Example: start a local Postgres container
docker run --name pubky-postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -p 127.0.0.1:5432:5432 \
  -d postgres:18
```

The `TEST_PUBKY_CONNECTION_STRING` environment variable is used by both testnet types to configure the database connection.

## EphemeralTestnet (Automated Tests)

All ports are random, all state is in-memory. Each instance gets its own isolated DHT and homeserver, so tests run in parallel without conflicts.

### Writing Tests

```rust,no_run
use pubky_testnet::EphemeralTestnet;

#[tokio::test]
#[pubky_testnet::test] // Cleans up ephemeral Postgres databases after the test
async fn my_test() {
    // Note: both attributes are required — #[tokio::test] provides the async
    // runtime, #[pubky_testnet::test] registers a cleanup hook for test DBs.
    // Run a new testnet. This creates a test DHT and homeserver.
    // By default, uses minimal_test_config() (admin/metrics disabled, no HTTP relay).
    let testnet = EphemeralTestnet::builder().build().await.unwrap();

    // Create a Pubky Http Client from the testnet.
    let client = testnet.client().unwrap();

    // Use the homeserver
    let homeserver = testnet.homeserver_app();
}
```

### Docker PostgreSQL

For testing without a separate Postgres installation, enable the `docker-postgres` feature:

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

This uses [testcontainers](https://docs.rs/testcontainers) to run PostgreSQL in a Docker container.
Docker must be running on the host. The container is automatically cleaned up on drop and on Ctrl+C/SIGTERM.

> **Important**: If you have multiple tests, see [Sharing Docker Postgres Across Tests](#sharing-docker-postgres-across-tests) below.

### Sharing Docker Postgres Across Tests

When using `docker-postgres`, each call to `.with_docker_postgres()` starts a **separate** PostgreSQL container.

Use `DockerPostgres::shared()` to start **one** container and share its connection string across all tests.
Docker handles cleanup automatically when the process exits.

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

### External PostgreSQL

If you prefer to use an external Postgres instance, set the `TEST_PUBKY_CONNECTION_STRING` environment variable:

```bash
TEST_PUBKY_CONNECTION_STRING='postgres://postgres:postgres@localhost:5432/postgres?pubky-test=true' \
  cargo test -p my-crate
```

Or pass the connection string programmatically:

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

The `?pubky-test=true` parameter tells the homeserver to create an ephemeral `pubky_test_*` database. The `#[pubky_testnet::test]` macro ensures the database is cleaned up after the test completes or panics.

### Custom Configuration

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

## StaticTestnet (CLI / Interactive)

A long-running testnet with fixed, well-known ports. Use this when external processes need to connect (browser tests, mobile apps, manual debugging).

### Fixed Ports

| Component | Port |
|-----------|------|
| DHT bootstrap node | `6881` |
| Pkarr relay | `15411` |
| HTTP relay | `15412` |
| Homeserver ICANN HTTP | `6286` |
| Homeserver Pubky HTTPS | `6287` |
| Homeserver admin | `6288` |

Homeserver address: `8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo`

### In-Memory Mode

State is lost on shutdown. Use `?pubky-test=true` to auto-create and clean up an ephemeral database:

```bash
TEST_PUBKY_CONNECTION_STRING='postgres://postgres:postgres@localhost:5432/postgres?pubky-test=true' \
  cargo run -p pubky-testnet
```

### Persistent Mode

State survives restarts. The data directory is auto-initialized on first run with a `config.toml` and server keypair. On subsequent runs, the existing state is picked up and the homeserver keeps the same identity.

```bash
TEST_PUBKY_CONNECTION_STRING='postgres://postgres:postgres@localhost:5432/postgres' \
  cargo run -p pubky-testnet -- persist ./my-testnet-data
```

The `TEST_PUBKY_CONNECTION_STRING` environment variable is read on every startup and overrides the `database_url` in the on-disk config.

> **Note**: For persistent mode, ensure `?pubky-test=true` is omitted so that the database is not cleaned up on shutdown.

### Custom Homeserver Config

Seed a custom config on first run (errors if `config.toml` already exists in the data directory):

```bash
TEST_PUBKY_CONNECTION_STRING='postgres://postgres:postgres@localhost:5432/postgres' \
  cargo run -p pubky-testnet -- --homeserver-config my-config.toml persist ./my-testnet-data
```
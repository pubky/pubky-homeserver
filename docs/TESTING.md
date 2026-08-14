# Testing

This guide is for contributors running Rust tests, integration tests, or CI jobs. For writing tests with a local testnet (ephemeral or persistent), see the [pubky-testnet README](../pubky-testnet/README.md).

## PostgreSQL for Tests

Many homeserver and testnet tests need PostgreSQL. Start a local instance with Docker:

```bash
docker run --name pubky-postgres \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -p 127.0.0.1:5432:5432 \
  -d postgres:18
```

Then run tests with a test connection string:

```bash
TEST_PUBKY_CONNECTION_STRING='postgres://postgres:postgres@localhost:5432/postgres?pubky-test=true' \
  cargo test -p pubky-homeserver --all-features
```

The `?pubky-test=true` parameter tells the test helpers to create an ephemeral `pubky_test_*` database inside the configured PostgreSQL instance. Databases are cleaned up after each test.

## Automatic Database Cleanup

Use the Pubky test macro to ensure ephemeral PostgreSQL databases are cleaned up:

```rust
#[tokio::test]
#[pubky_testnet::test]
async fn my_test() {
    // test code
}
```

The macro ensures registered test databases are dropped after the test completes or panics.

## Docker PostgreSQL in Tests

The `docker-postgres` feature lets tests automatically start a PostgreSQL container via Docker, removing the need for an external postgres instance. It's used by the [Rust examples](../examples/rust) and the pubky-testnet integration tests. It's a good option for self-contained tests or CI environments where you don't want to manage a separate database.

Enable it in your crate:

```toml
[dev-dependencies]
pubky-testnet = { version = "<version>", features = ["docker-postgres"] }
```

### Per-test container

Each `.with_docker_postgres()` call starts a separate PostgreSQL container. Simple but expensive for large test suites:

```rust
use pubky_testnet::EphemeralTestnet;

#[tokio::test]
async fn my_test() {
    let testnet = EphemeralTestnet::builder()
        .with_docker_postgres()
        .build()
        .await
        .unwrap();

    let homeserver = testnet.homeserver_app();
}
```

### Shared container

For many tests, share one Docker PostgreSQL instance with `DockerPostgres::shared()`. Each testnet still creates its own ephemeral database, so test data remains isolated:

```rust
use pubky_testnet::docker_postgres::DockerPostgres;
use pubky_testnet::EphemeralTestnet;

#[tokio::test]
async fn test_one() {
    let pg = DockerPostgres::shared().await;
    let testnet = EphemeralTestnet::builder()
        .postgres(pg.connection_string().unwrap())
        .build()
        .await
        .unwrap();

    let homeserver = testnet.homeserver_app();
}
```

## End-to-End Tests

The [`e2e`](../e2e) crate contains tests that cover cross-crate workflows using `pubky-testnet`. Run them with:

```bash
TEST_PUBKY_CONNECTION_STRING='postgres://postgres:postgres@localhost:5432/postgres?pubky-test=true' \
  cargo test -p e2e
```

## Common Commands

Run the homeserver tests against external PostgreSQL:

```bash
TEST_PUBKY_CONNECTION_STRING='postgres://postgres:postgres@localhost:5432/postgres?pubky-test=true' \
  cargo test -p pubky-homeserver --all-features
```

Run the testnet tests with Docker PostgreSQL:

```bash
cargo test -p pubky-testnet --features docker-postgres
```

Run the full workspace test suite:

```bash
TEST_PUBKY_CONNECTION_STRING='postgres://postgres:postgres@localhost:5432/postgres?pubky-test=true' \
  cargo test --workspace --all-features
```

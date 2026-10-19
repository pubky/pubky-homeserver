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
TEST_PUBKY_CONNECTION_STRING='postgres://postgres:postgres@localhost:5432/postgres' \
  cargo test -p pubky-homeserver --all-features
```

In test builds, each test automatically gets its own ephemeral `pubky_test_{uuid}` database on the configured server. Databases are cleaned up after each test.

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
TEST_PUBKY_CONNECTION_STRING='postgres://postgres:postgres@localhost:5432/postgres' \
  cargo test -p e2e
```

## Storage Backend Tests

Most tests run on the in-memory storage backend. Two kinds of tests cover the
backends a homeserver runs on in production:

- **Storage contract:** what the file service promises on every backend, such
  as overwrites, deletes, names that URLs percent-encode, multipart-sized
  writes, broken uploads, and downloads during an overwrite. Each case runs
  as a test of its own on each backend, under the layers production puts on
  it, named `memory::<case>`, `file_system::<case>`, and `gcs::<case>`. Add a
  case with `storage_contract_tests!` in
  [`opendal_service.rs`](../pubky-homeserver/src/persistence/files/opendal/opendal_service.rs).
- **Backend smoke tests:** the client API on a homeserver configured with
  `file_system` or `google_bucket` storage, in
  [`storage_backend_tests.rs`](../pubky-homeserver/src/client_server/storage_backend_tests.rs).

### Google Cloud Storage

The GCS tests run against a real bucket. They are marked `#[ignore]`, so
`cargo test` stays offline, and each has `gcs` in its name. To run them, set
both environment variables:

| Variable | Value |
| --- | --- |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to a service account JSON key |
| `GCS_BUCKET` | Name of the bucket |

```bash
GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json \
GCS_BUCKET=my-test-bucket \
TEST_PUBKY_CONNECTION_STRING='postgres://postgres:postgres@localhost:5432/postgres' \
  cargo nextest run -p pubky-homeserver --all-features \
    --run-ignored only -E 'test(/gcs/)'
```

A GCS test fails if a variable is missing, rather than passing without the
bucket. Each test works under a prefix of its own and deletes it when it
finishes, so tests can share a bucket and run in parallel. The prefix is
`ci/<run id>/<uuid>` in GitHub Actions and `test_<uuid>` otherwise.

Use a dedicated bucket. Give the service account only the
**Storage Object User** role on that bucket. Add lifecycle rules that delete
objects and incomplete multipart uploads older than one day, so that what a
killed test leaves behind is removed.

In CI, the [GCS Tests](../.github/workflows/gcs-tests.yml) workflow runs them
on pull requests, on pushes to `main`, and on demand. It reads the key from
the `GCS_CI_CREDENTIALS` secret and the bucket name from the `GCS_CI_BUCKET`
variable. Pull requests from forks and Dependabot don't get the secret, so
the workflow skips the tests with a warning; the push to `main` runs them
after the merge. On `main`, a missing secret fails the workflow.

## Docker Build Options

The root [Dockerfile](../Dockerfile) builds either a homeserver or a testnet image. Run the commands below from the repository root.

| Build argument | Values | Default |
| --- | --- | --- |
| `BUILD_TARGET` | `homeserver`, `testnet` | `homeserver` |
| `BUILD_PROFILE` | `release` (optimized and stripped), `debug` (faster development builds) | `release` |

Build a debug homeserver image:

```bash
docker build --build-arg BUILD_TARGET=homeserver --build-arg BUILD_PROFILE=debug -t pubky-homeserver:debug .
```

Build a release testnet image:

```bash
docker build --build-arg BUILD_TARGET=testnet --build-arg BUILD_PROFILE=release -t pubky-testnet:release .
```

Both images install their binary as `homeserver`. Check that it runs without starting services or connecting to PostgreSQL:

```bash
docker run --rm --network none pubky-homeserver:debug homeserver --help
docker run --rm --network none pubky-testnet:release homeserver --help
```

### Docker builds in CI

All Docker jobs use the shared [build workflow](../.github/workflows/docker-build.yml)
to build both `homeserver` and `testnet` images.

| Workflow | Trigger | Profile | Platforms | Publishes images |
| --- | --- | --- | --- | --- |
| [PR Check](../.github/workflows/pr-check.yml) | Pull requests and pushes to `main` | `debug` | `linux/amd64` (native runner) | No |
| [Release Docker check](../.github/workflows/docker-check.yml) | Pushes to `main` | `release` | `linux/amd64`, `linux/arm64` (native runners) | No |
| [Docker publishing](../.github/workflows/docker.yml) | Tags matching `v*` | `release` | `linux/amd64`, `linux/arm64` | Yes |

Callers must specify `build_profile`. Native checks default to `architecture: amd64`
and `publish: false`; setting `publish: true` builds and publishes both architectures.
The shared workflow derives runners, platforms, and cache scopes from these inputs.

Checks use native runners: `ubuntu-24.04` for AMD64 and `ubuntu-24.04-arm` for ARM64.
ARM64 is checked only after merging to `main`. Publishing runs on `ubuntu-latest`
with ARM64 emulation.

Caches use the scope `docker-<profile>-<target>-<architecture>`. Checks import and
update their cache, with debug builds on `main` warming caches for PRs. Publishing
imports both architecture-specific release caches from `main` without exporting.

## Common Commands

Run the homeserver tests against external PostgreSQL:

```bash
TEST_PUBKY_CONNECTION_STRING='postgres://postgres:postgres@localhost:5432/postgres' \
  cargo test -p pubky-homeserver --all-features
```

Run the testnet tests with Docker PostgreSQL:

```bash
cargo test -p pubky-testnet --features docker-postgres
```

Run the full workspace test suite:

```bash
TEST_PUBKY_CONNECTION_STRING='postgres://postgres:postgres@localhost:5432/postgres' \
  cargo test --workspace --all-features
```

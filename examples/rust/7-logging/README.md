# Logging example

Learn how to enable verbose tracing for the Pubky SDK before performing a simple storage roundtrip.

## Usage

By default, this example uses Docker to run PostgreSQL in a container for a fully self-contained setup. Docker must be running on the host.

```bash
cargo run --bin logging -- --level debug
```

### Using an external PostgreSQL instance

If you prefer to use your own PostgreSQL instance:

```bash
# Uses postgres://postgres:postgres@localhost:5432/postgres by default
cargo run --bin logging -- --level debug --external-postgres
```

You can specify a custom connection via the `TEST_PUBKY_CONNECTION_STRING` environment variable:

```bash
TEST_PUBKY_CONNECTION_STRING=postgres://user:pass@localhost:5432/mydb?pubky-test=true cargo run --bin logging -- --level debug --external-postgres
```

The `?pubky-test=true` parameter indicates that an ephemeral test database should be created.

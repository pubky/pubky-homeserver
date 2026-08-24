# Homeserver CLI

A command-line tool for administering a [pubky-homeserver](../pubky-homeserver).

## Installation

```sh
cargo install --path .
```

## Configuration

The admin password and endpoint can be supplied three ways. For each setting the
resolution order is **command-line flag → environment variable → config file**.

### Config file

Create a `config.toml`:

```toml
[admin]
admin_password = "your-admin-password"
admin_endpoint = "https://your-homeserver.example.com"
```

By default the CLI looks for `config.toml` in `~/.pubky`. Point it at a different
directory with `--data-dir` (or the `PUBKY_HOMESERVER_DATA_DIR` environment variable):

```sh
homeservercli --data-dir /path/to/config/dir info
```

### Environment variables

```sh
export PUBKY_HOMESERVER_ADMIN_PASSWORD="your-admin-password"
export PUBKY_HOMESERVER_ADMIN_ENDPOINT="https://your-homeserver.example.com"
export PUBKY_HOMESERVER_DATA_DIR="/path/to/config/dir"

homeservercli info
```

### Flags

```sh
homeservercli \
  --admin-endpoint https://your-homeserver.example.com \
  --admin-password your-admin-password \
  info
```

> Note: passing `--admin-password` on the command line exposes the value in your
> shell history and process list. Prefer the environment variable or config file.

## Usage

```
homeservercli [OPTIONS] <SUBCOMMAND>
```

### Global options

| Flag | Environment variable | Description |
|------|----------------------|-------------|
| `-d, --data-dir <PATH>` | `PUBKY_HOMESERVER_DATA_DIR` | Directory containing `config.toml` (default: `~/.pubky`) |
| `--admin-password <PASSWORD>` | `PUBKY_HOMESERVER_ADMIN_PASSWORD` | Admin API password |
| `--admin-endpoint <URL>` | `PUBKY_HOMESERVER_ADMIN_ENDPOINT` | Admin API base URL |
| `-v` / `-q` | | Increase / decrease log verbosity |

---

### `info`

Print homeserver statistics.

```sh
homeservercli info
```

---

### `signup-token generate`

Generate a signup invite token, optionally with custom quota limits.

```sh
homeservercli signup-token generate \
  [--storage-quota-mb <MB|unlimited>] \
  [--rate-read <rate>] \
  [--rate-write <rate>]
```

**Examples:**

```sh
# Unlimited storage, default rates
homeservercli signup-token generate --storage-quota-mb unlimited

# 500 MB storage, 10 MB/s read, 1 MB/s write
homeservercli signup-token generate \
  --storage-quota-mb 500 \
  --rate-read 10mb/s \
  --rate-write 1mb/s
```

---

### `user enable <PUBKY>`

Re-enable a previously disabled user account.

```sh
homeservercli user enable <PUBKY>
```

---

### `user disable <PUBKY>`

Disable a user account.

```sh
homeservercli user disable <PUBKY>
```

---

### `quota get <PUBKY>`

Show the effective quota for a user.

```sh
homeservercli quota get <PUBKY>
```

---

### `quota set <PUBKY>`

Override quota settings for a specific user. At least one quota flag is required.

```sh
homeservercli quota set <PUBKY> \
  [--storage-quota-mb <MB|unlimited>] \
  [--rate-read <rate>] \
  [--rate-write <rate>]
```

**Examples:**

```sh
# Set storage limit to 1 GB
homeservercli quota set <PUBKY> --storage-quota-mb 1024

# Remove storage limit
homeservercli quota set <PUBKY> --storage-quota-mb unlimited

# Set read rate to 5 MB/s
homeservercli quota set <PUBKY> --rate-read 5mb/s
```

---

## Rate limit format

Rate limits use the format `<number><unit>/<period>`:

- Units: `kb`, `mb`, `gb`
- Periods: `s` (second), `m` (minute), `h` (hour), `d` (day)
- Special value: `unlimited`

Examples: `100mb/s`, `10gb/h`, `unlimited`

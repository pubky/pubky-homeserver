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
listen_socket = "127.0.0.1:6288"
```

The `[admin]` section is compatible with the [pubky-homeserver](../pubky-homeserver)
config format, so you can point the CLI directly at a homeserver's own
`config.toml` (its `data_dir`) instead of maintaining a separate file. `listen_socket`
accepts a bare socket address (`host:port`), which defaults to the `http` scheme, or a
full URL (`https://your-homeserver.example.com`) when the admin API is behind TLS.

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

Print homeserver statistics (users, disk usage, signup codes, version).

```sh
homeservercli info
```

---

### `signup-tokens generate`

Generate a signup invite token, optionally with custom quota overrides for the
invited user. Omitted flags fall back to the system defaults defined in the
homeserver config.

```sh
homeservercli signup-tokens generate \
  [--storage-quota-mb <MB|unlimited>] \
  [--rate-read <rate>] \
  [--rate-write <rate>] \
  [--rate-read-burst <N>] \
  [--rate-write-burst <N>] \
  [--allowed-write-paths <PATH>]...
```

**Examples:**

```sh
# Unlimited storage, default rates
homeservercli signup-tokens generate --storage-quota-mb unlimited

# 500 MB storage, 10 MB/s read, 1 MB/s write
homeservercli signup-tokens generate \
  --storage-quota-mb 500 \
  --rate-read 10mb/s \
  --rate-write 1mb/s
```

---

### `users enable <PUBKY>`

Re-enable a previously disabled user account.

```sh
homeservercli users enable <PUBKY>
```

---

### `users disable <PUBKY>`

Disable a user account.

```sh
homeservercli users disable <PUBKY>
```

---

### `users quota-get <PUBKY>`

Show the effective quota for a user. The result is printed as JSON.

```sh
homeservercli users quota-get <PUBKY>
```

---

### `users quota-set <PUBKY>`

Override quota settings for a specific user. At least one quota flag is required.

Each scalar flag accepts `default` to remove the override and restore the
system default defined in the homeserver config.

```sh
homeservercli users quota-set <PUBKY> \
  [--storage-quota-mb <MB|unlimited|default>] \
  [--rate-read <rate|default>] \
  [--rate-write <rate|default>] \
  [--rate-read-burst <N|default>] \
  [--rate-write-burst <N|default>] \
  [--allowed-write-paths <PATH>]...
```

**Examples:**

```sh
# Set storage limit to 1 GB
homeservercli users quota-set <PUBKY> --storage-quota-mb 1024

# Remove storage limit
homeservercli users quota-set <PUBKY> --storage-quota-mb unlimited

# Reset the storage override back to the system default
homeservercli users quota-set <PUBKY> --storage-quota-mb default

# Set read rate to 5 MB/s
homeservercli users quota-set <PUBKY> --rate-read 5mb/s

# Restrict writes to specific paths (repeatable)
homeservercli users quota-set <PUBKY> \
  --allowed-write-paths /pub/tokens/ \
  --allowed-write-paths /pub/profile.json
```

---

## Rate limit format

Rate limits use the format `<number><unit>/<period>`:

- Units: `kb`, `mb`, `gb`
- Periods: `s` (second), `m` (minute), `h` (hour), `d` (day)
- Special value: `unlimited`

Examples: `100mb/s`, `10gb/h`, `unlimited`

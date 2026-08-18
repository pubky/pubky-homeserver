# Homeserver CLI

A command-line tool for administering a [pubky-homeserver](../pubky-homeserver).

## Installation

```sh
cargo install --path .
```

## Configuration

Create a `config.toml` in a directory of your choice:

```toml
[admin]
admin_password = "your-admin-password"
admin_endpoint = "https://your-homeserver.example.com"
```

Pass the directory path with `--data-dir`:

```sh
homeserver-cli --data-dir /path/to/config/dir admin info
```

Alternatively, supply credentials directly via flags (password will be prompted interactively):

```sh
homeserver-cli admin --admin-endpoint https://your-homeserver.example.com --admin-password info
```

## Usage

```
homeserver-cli [OPTIONS] admin [ADMIN OPTIONS] <SUBCOMMAND>
```

### Global options

| Flag | Description |
|------|-------------|
| `-d, --data-dir <PATH>` | Directory containing `config.toml` |
| `--admin-password` | Prompt for admin password interactively |
| `--admin-endpoint <URL>` | Admin API base URL |
| `-v` / `-q` | Increase / decrease log verbosity |

---

### `admin info`

Print homeserver statistics.

```sh
homeserver-cli admin info
```

---

### `admin signup-token generate`

Generate a signup invite token, optionally with custom quota limits.

```sh
homeserver-cli admin signup-token generate \
  [--storage-quota-mb <MB|unlimited>] \
  [--rate-read <rate>] \
  [--rate-write <rate>]
```

**Examples:**

```sh
# Unlimited storage, default rates
homeserver-cli admin signup-token generate --storage-quota-mb unlimited

# 500 MB storage, 10 MB/s read, 1 MB/s write
homeserver-cli admin signup-token generate \
  --storage-quota-mb 500 \
  --rate-read 10mb/s \
  --rate-write 1mb/s
```

---

### `admin user enable <PUBKY>`

Re-enable a previously disabled user account.

```sh
homeserver-cli admin user enable <PUBKY>
```

---

### `admin user disable <PUBKY>`

Disable a user account.

```sh
homeserver-cli admin user disable <PUBKY>
```

---

### `admin quota get <PUBKY>`

Show the effective quota for a user.

```sh
homeserver-cli admin quota get <PUBKY>
```

---

### `admin quota set <PUBKY>`

Override quota settings for a specific user. At least one quota flag is required.

```sh
homeserver-cli admin quota set <PUBKY> \
  [--storage-quota-mb <MB|unlimited>] \
  [--rate-read <rate>] \
  [--rate-write <rate>]
```

**Examples:**

```sh
# Set storage limit to 1 GB
homeserver-cli admin quota set <PUBKY> --storage-quota-mb 1024

# Remove storage limit
homeserver-cli admin quota set <PUBKY> --storage-quota-mb unlimited

# Set read rate to 5 MB/s
homeserver-cli admin quota set <PUBKY> --rate-read 5mb/s
```

---

## Rate limit format

Rate limits use the format `<number><unit>/<period>`:

- Units: `kb`, `mb`, `gb`
- Periods: `s` (second), `m` (minute), `h` (hour), `d` (day)
- Special value: `unlimited`

Examples: `100mb/s`, `10gb/h`, `unlimited`

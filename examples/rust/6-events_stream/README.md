# Event Stream

Subscribe to Server-Sent Events (SSE) from one or more Pubky users' homeserver `/events-stream` endpoint.

## Usage

```bash
cargo run --bin events_stream -- <USER_PUBKEY>... [OPTIONS]
```

### Options

- `<USER_PUBKEY>...`: One or more user public keys in z32 format (1-50 users)
- `--cursors <CURSORS>`: Comma-separated cursors for each user (optional, must match user count)
- `-l, --limit <N>`: Maximum number of events to fetch
- `-L, --live`: Enable live streaming mode (receive new events as they occur)
- `-r, --reverse`: Reverse chronological order (newest first)
- `-p, --path <PATH>`: Filter events by path prefix (e.g., `/pub/posts/`)
- `--testnet`: Use local testnet endpoints

## Examples

### Get last 10 events from a single user

```bash
cargo run --bin events_stream -- o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo --limit 10
```

### Live stream new events from multiple users

```bash
cargo run --bin events_stream -- \
  o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo \
  pxnu33x7jtpx9ar1ytsi4yxbp6a5o36gwhffs8zoxmbuptici1jy \
  --live
```

### Filter by path in reverse order

```bash
cargo run --bin events_stream -- o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo \
  --path "/pub/posts/" \
  --reverse \
  --limit 20
```

### Start from specific cursors for multiple users

```bash
cargo run --bin events_stream -- \
  o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo \
  pxnu33x7jtpx9ar1ytsi4yxbp6a5o36gwhffs8zoxmbuptici1jy \
  --cursors "1234567890,9876543210" \
  --limit 50
```

### Use with testnet

```bash
cargo run --bin events_stream -- 8pinxxgqs41n4aididenw5apqp1urfmzdztr8jt4abrkdn435ewo \
  --testnet \
  --live
```

## Output Format

Each event is printed as:

```
[PUT|DEL] <path> (cursor: <event_id>, hash: <content_hash>)
```

Example:
```
[PUT] pubky://o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo/pub/posts/123 (cursor: 42, hash: abc123...)
[DEL] pubky://o1gg96ewuojmopcjbz8895478wdtxtzzuxnfjjz8o8e77csa1ngo/pub/posts/456 (cursor: 43, hash: -)
```

# Request

Raw HTTP client powered by `PubkyHttpClient`. Works with plain HTTPS (including pkarr public-key hosts and `_pubky.<user>`).

## Usage

```bash
cargo run --bin request -- <METHOD> <URL> [--testnet] [-H "Name: value"] [-d DATA]
```

- `METHOD`: GET | POST | PUT | PATCH | DELETE | HEAD | OPTIONS
- `URL`: `https://_pubky.<user_pubky>/<path>`, or `https://example.com`
- `-H/--header`: repeatable header (`"Name: value"`)
- `-d/--data`: request body for POST/PUT/PATCH
- `--testnet`: resolve via local testnet (DHT + homeserver)

## Examples

```bash
# HTTPS to the _pubky (homeserver) subdomain form (use the raw z-base32 key)
cargo run --bin request -- GET https://_pubky.<user_z32>/pub/my-cool-app/info.json

# JSON POST with headers
cargo run --bin request -- \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"msg":"hello"}' \
  POST https://example.com/data.json

# Use local testnet endpoints
cargo run --bin request -- --testnet GET https://_pubky.<user_z32>/pub/my-cool-app/hello.txt
```

For example, at the time of writing, the following command returns the content of a user's social post from his pubky homeserver.

```
cargo run --bin request -- GET https://_pubky.operrr8wsbpr3ue9d4qj41ge1kcc6r7fdiy6o3ugjrrhi4y77rdo/pub/pubky.app/posts/0033X02JAN0SG
```

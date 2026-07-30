# Post-Setup

Common verification, production, and troubleshooting steps that apply to all deployment methods.

## Verification

### Find Your Public Key

The remaining checks need your homeserver's public key. The admin API binds to localhost, so run this from the server itself:

```bash
# Use your configured admin password. Default is "admin".
curl -s "http://127.0.0.1:6288/info" -H "X-Admin-Password: admin"
```

The response is JSON — look for the `public_key` field.

### Check PKARR Record

Look up your public key on [pkdns.net](https://pkdns.net/). The record should contain your `icann_domain` value and, if you set `public_ip`, your server's IP address.

For a more thorough check, resolve the record from the DHT directly using the `resolve` example from the [pkarr](https://github.com/pubky/pkarr) repository:

```bash
cargo run --example resolve <homeserver-public-key>
```

This performs a cold lookup, a cached lookup, and a network-only lookup, printing the resolved DNS records and timings for each.

### Check Pubky TLS

> **Note:** This only applies if your deployment supports Pubky TLS (port 6287 is publicly reachable). If you deployed with a [Cloudflare Tunnel](cloudflare-tunnel.md), skip this step.

From a separate machine with the [pkarr](https://github.com/pubky/pkarr) repository cloned:

```bash
cargo run --features=reqwest-builder --example http-get https://<homeserver-public-key>
```

A successful response prints `Pubky Homeserver`.

## Production Notes

- Back up the homeserver's state regularly:
  - The keypair at `~/.pubky/secret` — this is the homeserver's identity. If lost, the server cannot be recovered.
  - User data — by default stored in `~/.pubky/data/files` (depends on `storage.type`).
  - The PostgreSQL database.
- Change the default admin password in `[admin].admin_password`.

## Troubleshooting

### PKARR record missing or incorrect

Verify `icann_domain` (and `public_ip` if set) in `~/.pubky/config.toml`. After updating, restart the homeserver and allow a few minutes for the DHT record to propagate.

### Pubky TLS connections time out

Verify that port 6287 is open in your firewall and that the homeserver is listening on `0.0.0.0:6287`, not `127.0.0.1:6287`. Check with:

```bash
sudo ss -tlnp | grep 6287
```

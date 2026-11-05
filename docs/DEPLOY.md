# Deploy a Pubky Homeserver

How to make a Pubky homeserver reachable from the internet. This guide assumes you have already [installed the homeserver](./INSTALL.md) and have it running.

> **Note:** These guides cover homeserver-specific setup only, not general server hardening. If you're new to running public-facing servers, look into basic Linux server security before proceeding.

## Protocols

The homeserver speaks two protocols. Both serve the same data — the difference is how clients find and connect to your server:

- **Pubky TLS** (port 6287) — the native protocol. Clients resolve your homeserver's public key on the DHT and connect directly, bypassing any certificate authority.
- **HTTPS** (port 443) — standard web TLS. Browsers and the browser-based SDK use this, which requires a CA-issued certificate.

Ideally your deployment supports both, but some setups only provide HTTPS. The comparison table below shows what each option gives you.

## Choose Your Setup

There are three deployment guides depending on your requirements and network limitations. Compare them below and follow the one that fits your situation.

- **[With a Domain](deploy/domain.md)** — standard setup with a domain name and static IP. Long-lived certificates, full protocol support. The recommended production option.
- **[IP Address Only](deploy/ip-only.md)** — no domain registration needed. Uses short-lived certificates that auto-renew, so the server must stay healthy. Full protocol support.
- **[Cloudflare Tunnel](deploy/cloudflare-tunnel.md)** — no static IP or open ports needed. Cloudflare proxies HTTPS traffic through an outbound tunnel. Ideal for home servers behind NAT/CGNAT. **Does not support Pubky TLS.**

| | [Domain](deploy/domain.md) | [IP Address Only](deploy/ip-only.md) | [Cloudflare Tunnel](deploy/cloudflare-tunnel.md) |
| --- | --- | --- | --- |
| Static IP required | Yes | Yes | No |
| Domain required | Yes | No | Yes (Cloudflare-managed, from ~$5/year) |
| Open ports required | 80, 443, 6287 | 80, 443, 6287 | None |
| Pubky TLS (native) | Yes | Yes | No |
| HTTPS (browsers) | Yes | Yes | Yes |
| Certificate lifetime | 90 days (auto-renewed) | ~6 days (auto-renewed) | Managed by Cloudflare |
| Extra software | Caddy | Caddy (v2.10.1+) | cloudflared |
| Best for | Production servers | Quick setup, no domain | Home networks, no static IP |

## Client addresses and rate limits

Each listener has its own client identity setting:
`drive.icann_client_identity` for browser HTTP traffic and
`drive.pubky_client_identity` for Pubky TLS. Both default to `direct`.
The modes determine which client IP is used for IP-based rate limits:

- `direct` uses the TCP peer address. Behind a proxy, visitors share that
  proxy's IP-based limits.
- `proxy_protocol` requires a PROXY v1/v2 preface from a trusted proxy.
  The Caddy guides above use the
  [`reverse_proxy` transport option][caddy-proxy] to send it. For Pubky TLS,
  the preface must precede the TLS handshake.
- `http_header` reads a configured single-IP header on each request from a
  trusted proxy. The proxy must overwrite the header with the client's IP.

User-based limits remain separate. The `direct` and `proxy_protocol` modes
ignore HTTP client identity headers.

For HTTP header mode, edit `~/.pubky/config.toml`. Remove any existing
`icann_client_identity` inline setting from `[drive]`, then add this table
after the other `[drive]` settings:

```toml
[drive.icann_client_identity]
mode = "http_header"
header = "X-Real-IP"
trusted_proxies = ["127.0.0.1/32"]
```

Use the header your proxy overwrites and the proxy's immediate TCP source
address or network. Both proxy modes require a nonempty `trusted_proxies`
list. An allowed proxy can claim any client IP; connections from other peers
are closed before HTTP processing or the TLS handshake.

In `http_header` mode, every request must contain exactly one header value:
a bare IPv4 or IPv6 address, without a port. Missing, duplicate, or malformed
values receive `400 Bad Request`, even on routes without IP limits.
Address lists such as `X-Forwarded-For` chains are unsupported, and no other
header is used as a fallback. IPv4-mapped IPv6 addresses share limits with
their IPv4 equivalents.

For Cloudflare Tunnel, use `CF-Connecting-IP` as the header and trust only
the local connector's source address. Keeping `direct` mode continues to
share IP-based limits across visitors. See the
[Cloudflare Tunnel guide](deploy/cloudflare-tunnel.md).

Restart the homeserver after changing `config.toml`. See
[Run](INSTALL.md#run) in the install guide. For all configuration options, see
[`config.sample.toml`](../pubky-homeserver/config.sample.toml).

[caddy-proxy]: https://caddyserver.com/docs/caddyfile/directives/reverse_proxy#the-http-transport

# Deploy a Pubky Homeserver

How to make a Pubky homeserver reachable from the internet. This guide assumes you have already [installed the homeserver](./INSTALL.md) and have it running.

> **Note:** These guides cover homeserver-specific setup only, not general server hardening. If you're new to running public-facing servers, look into basic Linux server security before proceeding.

## Protocols

The homeserver speaks two protocols. Both serve the same data — the difference is how clients find and connect to your server:

- **Pubky TLS** (port 6287) — the native protocol. Clients resolve your homeserver's public key on the DHT and connect directly, bypassing any certificate authority.
- **HTTPS** (port 443) — standard web TLS. Browsers and the browser-based SDK use this, which requires a CA-issued certificate.

Ideally your deployment supports both, but some setups only provide HTTPS. The comparison table below shows what each option gives you.

## Choose Your Setup

| | [Domain](deploy/domain.md) | [IP Address Only](deploy/ip-only.md) | [Cloudflare Tunnel](deploy/cloudflare-tunnel.md) |
| --- | --- | --- | --- |
| Static IP required | Yes | Yes | No |
| Domain required | Yes | No | Yes (on Cloudflare) |
| Open ports required | 80, 443, 6287 | 80, 443, 6287 | 6287 only (if reachable) |
| Pubky TLS (native) | Yes | Yes | Only if port 6287 is reachable |
| HTTPS (browsers) | Yes | Yes | Yes |
| Certificate lifetime | 90 days (auto-renewed) | ~6 days (auto-renewed) | Managed by Cloudflare |
| Extra software | Caddy | Caddy (v2.10.1+) | cloudflared |
| Best for | Production servers | Quick setup, no domain | Home networks, no static IP |

Pick an option and follow the linked guide:

- **[With a Domain](deploy/domain.md)** — standard setup with a domain name and static IP. Long-lived certificates, full protocol support. The recommended production option.
- **[IP Address Only](deploy/ip-only.md)** — no domain registration needed. Uses short-lived certificates that auto-renew, so the server must stay healthy. Full protocol support.
- **[Cloudflare Tunnel](deploy/cloudflare-tunnel.md)** — no static IP or open ports needed for HTTPS. Cloudflare proxies traffic through an outbound tunnel. Ideal for home servers behind NAT/CGNAT. Pubky TLS requires port 6287 to be separately reachable.

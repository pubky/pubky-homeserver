# Deploy a Pubky homeserver

Make an [installed, running homeserver](INSTALL.md) reachable from the internet.
These guides cover homeserver-specific settings. Use your provider's official
instructions for DNS, firewall rules, and general server administration.

## Protocols

Both protocols serve the same data:

- **Pubky TLS** (port 6287): native clients resolve the homeserver's public key
  through PKARR and connect directly, without a certificate authority.
- **HTTPS** (port 443): browsers and the browser SDK connect using a CA-issued
  certificate, with TLS terminated by nginx or Cloudflare.

## Choose your setup

- **[Public IP with nginx](deploy/public-ip.md)**: recommended for production.
  Requires a static public IP and inbound ports 80, 443, and 6287. A domain is
  optional. Supports both protocols.
- **[Cloudflare Tunnel](deploy/cloudflare-tunnel.md)**: for networks without a
  static IP or inbound ports, including NAT/CGNAT. Requires a Cloudflare-managed
  domain. Supports HTTPS only.

## Client addresses and rate limits

PROXY protocol support requires homeserver **v0.17.0 or later**.

From v0.17.0, IP-based limits use the TCP client address, ignoring
`X-Forwarded-For`, `X-Real-IP`, and `CF-Connecting-IP`. User-based limits still
use user keys.

Under `[drive]`, `icann_client_identity` controls the HTTP listener (6286) and
`pubky_client_identity` controls Pubky TLS (6287). Both default to `direct`.
Behind a proxy, this groups clients under the proxy's IP-based limits.

For separate client IPs, use `proxy_protocol` with a proxy that sends PROXY v1
or v2. This mode requires a valid preface from a peer in `trusted_proxies`;
it cannot also accept ordinary direct connections. See the
[homeserver configuration](deploy/public-ip.md#configure-the-homeserver) and
[nginx setup](deploy/nginx.md).

### Optional: proxy Pubky TLS

Direct Pubky TLS connections in `direct` mode are recommended for a single
server: the homeserver handles TLS and receives client IPs directly.

Pubky TLS also supports a TCP proxy, such as nginx stream, while preserving
client IPs through PROXY protocol. Set `drive.pubky_client_identity` to
`proxy_protocol` with `trusted_proxies`, and restrict backend access to the
proxy. The proxy must send the PROXY preface before passing TLS through to the
homeserver, which still terminates TLS. Publish the proxy's public address and
port in PKARR. See the
[configuration reference](../pubky-homeserver/config.sample.toml).

### Upgrade an existing proxy deployment

Upgrade to v0.17.0 or later using the [install guide](INSTALL.md). Stop the old
homeserver before replacing its binary or container.
If your deployment relied on forwarding headers, follow the nginx setup above.
Apply proxy and homeserver changes together; mismatched modes interrupt
requests.

If you followed the previous Caddy domain or IP-only guide, prepare nginx and
its certificates first, then validate with `sudo nginx -t`. During the cutover,
run `sudo systemctl disable --now caddy` to free ports 80 and 443. Restart the
homeserver with the new `proxy_protocol` settings, then start nginx with
`sudo systemctl enable --now nginx`. Expect a brief interruption while switching.

HTTP tunnels must instead keep `direct` mode and account for
[shared IP-based limits][tunnel-limits].

[tunnel-limits]: deploy/cloudflare-tunnel.md#client-addresses-and-rate-limits

# Deploy with a Cloudflare Tunnel

Expose an [installed homeserver](../INSTALL.md) over HTTPS without a static IP
or inbound ports. You need a Cloudflare account, a domain managed by Cloudflare,
and `cloudflared` running on the homeserver machine.

This HTTP tunnel does not expose Pubky TLS. For native connectivity, use the
[public IP setup](public-ip.md) with or without a domain.

## Configure the homeserver

Edit the existing settings in `~/.pubky/config.toml`. Replace `YOUR_DOMAIN` with
the hostname you will route through the tunnel, such as
`homeserver.example.com`:

```toml
[drive]
icann_listen_socket = "127.0.0.1:6286"
icann_client_identity = { mode = "direct" }

[pkdns]
icann_domain = "YOUR_DOMAIN"
```

Keep `public_ip` and `pubky_listen_socket` at their loopback defaults for this
setup. Restart the homeserver using the [install guide](../INSTALL.md#run).
For other settings, see the
[configuration reference](../../pubky-homeserver/config.sample.toml).

## Configure the tunnel

Follow Cloudflare's [locally managed tunnel instructions][tunnel-setup] to
install `cloudflared`, authenticate, create a tunnel, and route `YOUR_DOMAIN`
to it. In the tunnel's `config.yml`, keep the tunnel ID and credentials path.
Replace the example `url` setting with this ingress configuration:

```yaml
ingress:
  - hostname: YOUR_DOMAIN
    service: http://127.0.0.1:6286
  - service: http_status:404
```

Start the tunnel using Cloudflare's instructions and
[run it as a service][tunnel-service] so it survives reboots. Then follow the
[common verification and production steps](post-setup.md).

## Client addresses and rate limits

Keep `icann_client_identity` in `direct` mode: this HTTP tunnel sends no PROXY
preface, so `proxy_protocol` mode rejects its connections.

Visitors share `cloudflared`'s IP-based request-count limits (`127.0.0.1` here).
Unauthenticated requests also share IP-based bandwidth limits; user-based
limits remain separate. Forwarding headers do not restore separate client
identities, including when upgrading from a setup that relied on them.

Consider [Cloudflare rate limiting rules][cloudflare-rate-limits] to limit
requests by visitor IP before they reach the tunnel. For separate IP-based
limits at the homeserver, use the [public IP setup](public-ip.md) with PROXY
protocol.

## Troubleshooting

### Tunnel connects but HTTPS returns 502

Check that the homeserver responds on its local HTTP listener:

```bash
curl -I http://127.0.0.1:6286
```

Expect `200 OK`. If the homeserver logs
`Rejected connection during client identification`, set
`icann_client_identity` to `{ mode = "direct" }` and restart it.

For tunnel errors, see [Cloudflare troubleshooting][tunnel-troubleshooting].
For PKARR issues, see [common troubleshooting](post-setup.md#troubleshooting).

[tunnel-setup]: https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/create-local-tunnel/
[tunnel-service]: https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/do-more-with-tunnels/local-management/as-a-service/linux/
[tunnel-troubleshooting]: https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/troubleshoot-tunnels/
[cloudflare-rate-limits]: https://developers.cloudflare.com/waf/rate-limiting-rules/

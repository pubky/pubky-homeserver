# Deploy with a domain or IP address

Expose an [installed homeserver](../INSTALL.md) over HTTPS and Pubky TLS using
nginx on the same machine. You need a static public IPv4 address. You can use
a domain with access to its DNS settings, or use the IP address directly.

This setup requires homeserver **v0.17.0 or later** for PROXY protocol support.

## Open ports

Allow inbound traffic on these ports using your hosting provider's or
firewall's documentation:

- **80**: HTTP certificate validation and HTTPS redirects.
- **443**: HTTPS, terminated by nginx.
- **6287**: direct Pubky TLS connections.

Keep the HTTP backend (6286), admin API (6288), and metrics (6289) bound to
`127.0.0.1` and inaccessible from the internet.

## Configure the homeserver

Edit the existing settings in `~/.pubky/config.toml`. Replace `YOUR_IP` with
this server's static public IPv4 address and `PUBLIC_ADDRESS` with your domain
(or the same IP address for an IP-only deployment):

```toml
[drive]
pubky_listen_socket = "0.0.0.0:6287"

# Accept client addresses from the local nginx proxy.
[drive.icann_client_identity]
mode = "proxy_protocol"
trusted_proxies = ["127.0.0.1/32"]

[pkdns]
public_ip = "YOUR_IP"
icann_domain = "PUBLIC_ADDRESS"
```

Keep `pubky_client_identity` at its default `direct` mode and the other
listeners on loopback. Complete the nginx setup before restarting the
homeserver so both sides use matching client-identity modes.
See the [configuration reference](../../pubky-homeserver/config.sample.toml)
for other settings. A separate ingress gateway can instead use the
[optional Pubky TLS proxy setup](../DEPLOY.md#optional-proxy-pubky-tls).

## Set up DNS (domain only)

For a domain, create an A record pointing to `YOUR_IP` using your DNS provider's
instructions. Add an AAAA record only if nginx will also be reachable over IPv6;
the nginx guide below includes the required listeners. Skip DNS for IP-only
deployments.

## Set up nginx

Continue with the [nginx guide](nginx.md) for certificates, HTTPS, and PROXY
protocol, then [verify the deployment](post-setup.md). The verification guide
also covers backups and homeserver troubleshooting.

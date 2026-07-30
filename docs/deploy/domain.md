# Deploy with a Domain

How to deploy a Pubky homeserver using a domain name and a static IP address. This gives you full connectivity: both HTTPS (for browsers) and Pubky TLS (the native protocol).

This guide assumes you have already [installed the homeserver](../INSTALL.md) and have it running.

Commands and package names assume a Debian-based system (Ubuntu, Debian, etc.), adapt as needed for other distributions.

## Requirements

- A server with a **static public IP address**
- A **domain name** with access to its DNS settings
- Ports 80, 443, and 6287 available for inbound traffic

## Open Ports

The homeserver speaks two protocols. Both endpoints serve the same data, the difference is how clients find and connect to your server:

**Pubky TLS** is the native protocol: clients resolve your homeserver's public key on the DHT and connect directly on port 6287, bypassing any certificate authority.

**CA-authenticated TLS** is the HTTPS you already know from the regular internet: browsers and the browser-based SDK use this on port 443, which requires a TLS certificate from a certificate authority for your domain.

The homeserver serves plain HTTP on an internal port; we place [Caddy](https://caddyserver.com/) in front of it to add the CA-authenticated TLS layer and serve HTTPS on port 443. Caddy manages the certificates automatically.

Open these three ports for inbound traffic:

| Port | Purpose |
| --- | --- |
| 80 | HTTP — [Caddy](#set-up-caddy) needs this for automatic TLS certificate provisioning. |
| 443 | HTTPS — serves your homeserver via [Caddy](#set-up-caddy). Also used for TLS-ALPN-01 certificate challenges. |
| 6287 | Pubky TLS — direct Pubky protocol connections (no certificate needed). |

How you open these depends on your setup: a cloud provider's security group, a router's port-forwarding rules, or a host firewall.

Do **not** expose these ports directly to the internet:

| Port | Purpose |
| --- | --- |
| 6286 | ICANN HTTP — Caddy proxies to this internally. |
| 6288 | Admin API — admin operations. |
| 6289 | Metrics — internal monitoring only. |

## Configure the Homeserver

Edit `~/.pubky/config.toml` with the following settings:

```toml
[drive]
# Listen on all interfaces so Pubky TLS is reachable from the internet
pubky_listen_socket = "0.0.0.0:6287"

# icann_listen_socket defaults to 127.0.0.1:6286 — no change needed.

[pkdns]
# The public-facing IP of this machine. Published to the DHT so that
# Pubky TLS clients can connect directly to the homeserver.
public_ip = "YOUR_IP"

# Your domain name for HTTPS browser access.
icann_domain = "YOUR_DOMAIN"
```

Replace `YOUR_IP` with the public IP of the machine running the homeserver. You can find it with `curl -4 ifconfig.me`.

Replace `YOUR_DOMAIN` with your domain name.

> **Warning:** Do **not** apply `0.0.0.0` to `icann_listen_socket`, `admin.listen_socket`, or `metrics.listen_socket` — those must stay on `127.0.0.1` to avoid exposing internal APIs to the internet.

> **Important:** Ensure your server has a **static (reserved) public IP**. If your IP changes then the PKARR record (which embeds `public_ip`), your Caddy configuration, and any DNS records will silently point at a dead address.

Restart the homeserver after editing `config.toml` for the changes to take effect. See [Run](../INSTALL.md#run) in the install guide.

> For the full list of settings (including `public_pubky_tls_port` and `public_icann_http_port` for non-standard port setups), see [`pubky-homeserver/config.sample.toml`](../../pubky-homeserver/config.sample.toml).

## Set Up DNS

Configure your domain with an A record pointing to your server's public IP. If your server also has a public IPv6 address, add an AAAA record too.

| Record Type | Name | Value |
| --- | --- | --- |
| A | YOUR_DOMAIN | YOUR_IPV4_ADDRESS |
| AAAA | YOUR_DOMAIN | YOUR_IPV6_ADDRESS (optional) |

Wait for DNS propagation, then verify:

```bash
dig +short YOUR_DOMAIN        # A record
dig +short AAAA YOUR_DOMAIN   # AAAA record (if configured)
```

These should return your server's public IP(s).

## Set Up Caddy

Install [Caddy](https://caddyserver.com/docs/install#debian-ubuntu-raspbian).

> **Prerequisites:** [DNS propagation](#set-up-dns) must be complete before this step, and [port 80 must be open](#open-ports). Caddy uses port 80 to complete the ACME challenge when obtaining a TLS certificate — if either DNS or port 80 are not ready then certificate provisioning will fail.

Edit the Caddyfile:

```bash
sudo nano /etc/caddy/Caddyfile
```

Replace its contents with:

```
your_domain.com {
    reverse_proxy 127.0.0.1:6286
}
```

> **Important:** The domain in the Caddyfile must exactly match both your DNS A-record name and the `icann_domain` value in `config.toml`. A mismatch between any of these is a common source of silent failures.

Reload Caddy and check the logs:

```bash
sudo systemctl reload caddy
journalctl -u caddy --no-pager | tail -50
```

Look for "certificate obtained" to confirm success, or any ACME errors.

> **Tip:** The most common cause of ACME certificate errors is port 80 not being reachable from the internet. If you see an ACME error in the logs then double-check your firewall rules.

## Verify the Deployment

### Check ICANN HTTPS

From your local machine, verify that HTTP redirects to HTTPS and the homeserver responds. Replace `YOUR_DOMAIN` with your domain:

```bash
# Should redirect to HTTPS (Caddy returns 308 by default)
curl -I http://YOUR_DOMAIN

# Should return 200
curl -I https://YOUR_DOMAIN
```

### Find Your Public Key

The remaining checks need your homeserver's public key. The admin API binds to localhost, so run this from the server itself:

```bash
# Use your configured admin password. Default is "admin".
curl -s "http://127.0.0.1:6288/info" -H "X-Admin-Password: admin"
```

The response is JSON — look for the `public_key` field.

### Check PKARR Record

Look up your public key on [pkdns.net](https://pkdns.net/). The record should contain your server's public IP and your domain (from `icann_domain`).

For a more thorough check, resolve the record from the DHT directly using the `resolve` example from the [pkarr](https://github.com/pubky/pkarr) repository:

```bash
cargo run --example resolve <homeserver-public-key>
```

This performs a cold lookup, a cached lookup, and a network-only lookup, printing the resolved DNS records and timings for each. Verify that the output contains an `A` record with your server's public IP and `HTTPS` (SVCB) records — one for the Pubky TLS port and one pointing to your domain.

### Check Internal Ports Are Not Exposed

```bash
# These should all fail/timeout from an external machine:
curl http://YOUR_DOMAIN:6286   # ICANN HTTP (internal)
curl http://YOUR_DOMAIN:6288   # Admin API
curl http://YOUR_DOMAIN:6289   # Metrics
```

### Check Pubky TLS

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

### Caddy fails to obtain a certificate

Ensure ports 80 and 443 are open and reachable from the internet. Caddy attempts ACME challenges on both port 80 (HTTP-01) and port 443 (TLS-ALPN-01) — both should be open. Check your cloud firewall and any host-level firewall (`ufw`, `iptables`).

Verify that DNS has propagated — `dig +short YOUR_DOMAIN` should return your IP.

### Pubky TLS connections time out

Verify that port 6287 is open in your firewall and that the homeserver is listening on `0.0.0.0:6287`, not `127.0.0.1:6287`. Check with:

```bash
sudo ss -tlnp | grep 6287
```

### PKARR record shows wrong IP

Check `pkdns.public_ip` in `~/.pubky/config.toml`. It must be the server's public IP, not a private or localhost address. After updating, restart the homeserver and allow a few minutes for the DHT record to propagate.

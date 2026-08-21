# Deploy with a Cloudflare Tunnel

How to deploy a Pubky homeserver behind a Cloudflare Tunnel — no open ports or static IP needed.

> **Important limitation:** Cloudflare Tunnels only proxy HTTP/HTTPS traffic. **Pubky TLS (the native protocol on port 6287) will not work with this setup.** Your homeserver will be reachable by browsers and the browser-based SDK over HTTPS, but not by native Pubky protocol clients. If you can open ports, consider [deploying with a domain](domain.md) or [deploying with an IP address](ip-only.md) instead — both support full Pubky TLS connectivity.

This guide assumes you have already [installed the homeserver](../INSTALL.md) and have it running.

Commands and package names assume a Debian-based system (Ubuntu, Debian, etc.), adapt as needed for other distributions.

## Requirements

- A free [Cloudflare account](https://dash.cloudflare.com/sign-up)
- A **domain name** with its DNS managed by Cloudflare (free plan is fine) — you can [buy one from Cloudflare](https://developers.cloudflare.com/registrar/get-started/register-domain/) for under $10/year or [transfer an existing domain](https://developers.cloudflare.com/fundamentals/setup/manage-domains/add-site/)
- `cloudflared` installed on the server

## Install cloudflared

Install the `cloudflared` daemon following [Cloudflare's official instructions](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/).

## Authenticate with Cloudflare

```bash
cloudflared login
```

Select the domain you want to use in the browser window that opens and authorize `cloudflared`. A certificate is saved to `~/.cloudflared/cert.pem`.

## Create the Tunnel

```bash
cloudflared tunnel create pubky-homeserver
```

Note the **Tunnel ID** (a UUID) from the output — you'll need it for the next steps. A credentials file is created at `~/.cloudflared/<TUNNEL_ID>.json`.

## Route DNS

```bash
cloudflared tunnel route dns pubky-homeserver YOUR_DOMAIN
```

Replace `YOUR_DOMAIN` with your domain or subdomain (e.g. `homeserver.example.com`). This creates a CNAME record in Cloudflare DNS pointing to the tunnel.

## Configure the Tunnel

Create `~/.cloudflared/config.yml`:

```yaml
tunnel: <TUNNEL_ID>
credentials-file: /home/<YOUR_USER>/.cloudflared/<TUNNEL_ID>.json

ingress:
  - hostname: YOUR_DOMAIN
    service: http://127.0.0.1:6286
  - service: http_status:404
```

Replace `<TUNNEL_ID>`, `<YOUR_USER>`, and `YOUR_DOMAIN` with your values.

The ingress rule sends traffic for your domain to the homeserver's internal HTTP port (6286). The catch-all rule at the bottom returns 404 for anything else.

## Configure the Homeserver

Edit `~/.pubky/config.toml`:

```toml
[pkdns]
# Set to 443 since Cloudflare terminates TLS and browsers connect
# on the standard HTTPS port.
public_icann_http_port = 443

# Your domain name — the tunnel makes this reachable via Cloudflare.
icann_domain = "YOUR_DOMAIN"

# public_ip is not needed — Cloudflare proxies all traffic, so there is
# no direct IP for Pubky TLS clients to connect to.

# pubky_listen_socket can stay at the default (127.0.0.1:6287) since
# Pubky TLS is not used with this setup.
```

Restart the homeserver after editing `config.toml`. See [Run](../INSTALL.md#run) in the install guide.

> For the full list of settings, see [`pubky-homeserver/config.sample.toml`](../../pubky-homeserver/config.sample.toml).

## Run the Tunnel

### Test manually first

```bash
cloudflared tunnel run pubky-homeserver
```

Verify that `https://YOUR_DOMAIN` responds (see [Verify](#verify-the-deployment) below). Press Ctrl+C to stop.

### Install as a system service

Once the manual test passes, install `cloudflared` as a systemd service so it starts on boot. You must pass the config path explicitly because `sudo` changes the home directory to `/root`:

```bash
sudo cloudflared --config ~/.cloudflared/config.yml service install
sudo systemctl enable cloudflared
sudo systemctl start cloudflared
```

Check the service status:

```bash
sudo systemctl status cloudflared
journalctl -u cloudflared --no-pager | tail -20
```

## Verify the Deployment

### Check ICANN HTTPS

From your local machine:

```bash
# Should return 200
curl -I https://YOUR_DOMAIN
```

Then follow the [common verification steps](post-setup.md) to find your public key and check your PKARR record. (The Pubky TLS check does not apply to this setup.)

## Production Notes

See the [common production notes](post-setup.md#production-notes), plus:

- Back up `~/.cloudflared/` — contains your tunnel credentials. If lost, you'll need to recreate the tunnel.
- The tunnel must stay running for HTTPS to work. Monitor the `cloudflared` service and set up alerts if it goes down.
- Cloudflare's free plan has no bandwidth caps for tunnels, but review their [terms of service](https://www.cloudflare.com/terms/) for your use case.

## Troubleshooting

### Tunnel connects but HTTPS returns 502

The tunnel is reaching Cloudflare but can't connect to the homeserver locally. Verify the homeserver is running and listening on port 6286:

```bash
curl -I http://127.0.0.1:6286
sudo ss -tlnp | grep 6286
```

### cloudflared won't start

Check the credentials file exists and matches the tunnel ID in `config.yml`:

```bash
ls ~/.cloudflared/*.json
cat ~/.cloudflared/config.yml
```

If you moved or recreated the tunnel, the credentials file path may have changed.

For PKARR troubleshooting, see [common troubleshooting](post-setup.md#troubleshooting).

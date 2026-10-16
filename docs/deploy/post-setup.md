# Verify and maintain a deployment

Use these checks after configuring nginx or Cloudflare Tunnel.

## Verification

### Check HTTPS

From a separate machine, replace `PUBLIC_ADDRESS` with your configured domain
or public IP address:

```bash
curl -i https://PUBLIC_ADDRESS/
```

Expect `200 OK` and `Pubky Homeserver`. For nginx deployments, also check the
HTTP redirect:

```bash
curl -I http://PUBLIC_ADDRESS/
```

Expect `301` with a `Location` header pointing to the HTTPS address.

### Find your public key

On the server, query the local admin API using your configured admin password
(the default is `admin`):

```bash
curl -s http://127.0.0.1:6288/info -H "X-Admin-Password: admin"
```

Replace `HOMESERVER_PUBLIC_KEY` below with the response's `public_key` value.

### Check PKARR record

Look up the public key on [pkdns.net](https://pkdns.net/). Expect an HTTPS
(SVCB) record targeting your `icann_domain`, plus a native Pubky TLS record
and an address record for `public_ip`.

For domain and IP-only deployments, the address must be your server's public
IP. Cloudflare deployments using the defaults still publish `127.0.0.1` and
a native TLS record; these do not provide public Pubky TLS connectivity.
Check the tunnel hostname in the HTTPS target instead.

For a direct DHT lookup, run the following from a clone of the
[pkarr repository](https://github.com/pubky/pkarr):

```bash
cargo run --example resolve HOMESERVER_PUBLIC_KEY
```

### Check Pubky TLS

Skip this check for Cloudflare Tunnel. For domain and IP-only deployments,
run this from a separate machine, in a clone of the pkarr repository:

```bash
cargo run --features=reqwest-builder --example http-get \
  https://HOMESERVER_PUBLIC_KEY
```

A successful response prints `Pubky Homeserver`.

## Production notes

Back up the homeserver's identity and persistent data:

- `~/.pubky/secret`: the server keypair, required to preserve its identity.
- User data: by default, `~/.pubky/data/files` (depends on `storage.type`).
  Uploads staged in `~/.pubky/data/files-tmp` need no backup. If using a
  separate data volume, mount `~/.pubky/data`, not `data/files`.
- The PostgreSQL database. See the
  [PostgreSQL backup documentation][postgres-backup] for backup methods.

Change the default admin password in `[admin].admin_password`.

## Troubleshooting

### PKARR record missing or incorrect

Check `icann_domain` and, for direct deployments, `public_ip` in
`~/.pubky/config.toml`. After updating, restart the homeserver and allow a few
minutes for the DHT record to propagate.

### Pubky TLS connections time out

Check that port 6287 is open and the homeserver listens on `0.0.0.0:6287`:

```bash
sudo ss -tlnp | grep 6287
```

### Proxy requests fail or return 502

For `Rejected connection during client identification`, check that the proxy
sends a valid preface and its actual TCP address is in `trusted_proxies`.
Container networking may change that address. For Pubky TLS, the preface must
precede the TLS handshake.

A preface sent to a `direct` listener breaks HTTP parsing or TLS. Match the
modes on both ends, then use the diagnostic below for a PROXY-enabled backend.
For HTTP tunnels, use the
[Cloudflare checks](cloudflare-tunnel.md#troubleshooting).

### Check the HTTP listener with PROXY protocol

With curl 8.2.0 or later, run this on the homeserver machine. The HTTP listener
must use `proxy_protocol` mode and trust `127.0.0.1/32`:

```bash
curl --noproxy '*' --max-time 5 -i \
  --haproxy-clientip 198.51.100.10 http://127.0.0.1:6286/
```

[`--haproxy-clientip`][curl-haproxy-clientip] sends a PROXY v1 preface declaring
the client IP. The actual TCP peer must still be trusted.
Expect `200 OK` and `Pubky Homeserver`.

This checks the backend only. Test public HTTPS separately without this option;
public nginx and Cloudflare endpoints do not expect a preface.

To debug a `key = "ip"` rule, use its path and method. Repeat requests with the
same declared IP, then change it to check for a separate quota. Use separate
curl invocations to open a new TCP connection each time.

### Different visitors share IP-based limits

Check the listener's mode against the
[client address guidance](../DEPLOY.md#client-addresses-and-rate-limits).
`direct` mode groups requests by the proxy's address, as expected with
[Cloudflare Tunnel](cloudflare-tunnel.md#client-addresses-and-rate-limits).

[curl-haproxy-clientip]: https://curl.se/docs/manpage.html#--haproxy-clientip
[postgres-backup]: https://www.postgresql.org/docs/current/backup.html

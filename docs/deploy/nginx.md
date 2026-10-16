# Configure nginx for HTTPS and client addresses

Continue here after configuring the homeserver in the
[public IP deployment guide](public-ip.md). nginx terminates HTTPS and forwards
HTTP with the client address to `127.0.0.1:6286`.

Install homeserver **v0.17.0 or later** before enabling `proxy_protocol on`.

This setup uses nginx's [stream proxy module][stream-proxy] with
[stream TLS support][stream-tls]. The HTTP `proxy_pass` directive does not
send a PROXY preface upstream.

Paths and commands assume Linux with systemd and one domain or IPv4 address.
This stream listener needs port 443; adapt the layout if nginx already serves
other HTTPS sites. Clients must connect directly to nginx, without a proxy or
CDN in front of it.

If your domain has an AAAA record, also add `listen [::]:80;` to the HTTP
server block and `listen [::]:443 ssl;` to the stream server block below.
Both advertised address families must reach nginx.

## Install nginx

Follow the [official installation instructions][nginx-install]. Ensure the
stream and stream TLS modules are available and loaded; distribution packages
may provide stream support separately (for example, `libnginx-mod-stream` on
Debian or Ubuntu).

## Certificate

Obtain a CA-issued certificate for your `PUBLIC_ADDRESS` before loading the
HTTPS listener:

- **Domain**: follow [Certbot's instructions][certbot-install].
- **IP address**: follow
  [Let's Encrypt's IP certificate guide][ip-certificates].
  Certbot's webroot method requires version 5.4 or later. IP certificates expire
  in about six days, so reliable automatic renewal is essential.

Use [Certbot's `certonly` command][certbot-commands] to obtain the certificate,
then configure the stream listener below.

Set up [automatic renewal][certbot-renewal] and reload nginx after renewal so
it serves the new certificate. Keep the validation path and ports required by
your chosen certificate method available.

## Configure the HTTPS stream listener

Add this to `/etc/nginx/nginx.conf` outside `http`, keeping module-loading
directives. If `stream` already exists, add only its `server` block. Do not
place this in `conf.d`, which is included inside `http`. Replace the two
`/path/to/` values with your certificate chain and private key paths.

```nginx
stream {
    server {
        listen 443 ssl;
        ssl_certificate /path/to/fullchain.pem;
        ssl_certificate_key /path/to/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;

        proxy_pass 127.0.0.1:6286;
        proxy_protocol on;
    }
}
```

`proxy_protocol on` sends the client's address in a PROXY v1 preface. The
homeserver settings from your deployment guide accept it from `127.0.0.1`.
Restrict backend access to nginx: trusted peers can claim any client IP.

To redirect HTTP to HTTPS, create `/etc/nginx/conf.d/pubky-http.conf` inside
nginx's `http` configuration. Replace `PUBLIC_ADDRESS` with your domain or
public IPv4 address. Preserve any HTTP certificate-validation location required
by your certificate provider.

```nginx
server {
    listen 80;
    server_name PUBLIC_ADDRESS;

    location / {
        return 301 https://$http_host$request_uri;
    }
}
```

Apply both nginx and homeserver changes together; requests fail while their
PROXY protocol settings differ:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

Restart the homeserver as described in [Run](../INSTALL.md#run), then follow
the [common verification and production steps](post-setup.md).

## Troubleshooting

### nginx reports an unknown stream directive

Install and load the stream module, and place `stream` outside `http`.
Other distributions also need stream TLS support.

### HTTPS connects but requests fail

Check `/var/log/nginx/error.log` and the homeserver logs, then follow
[common troubleshooting](post-setup.md#proxy-requests-fail-or-return-502).

[stream-proxy]: https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html
[stream-tls]: https://nginx.org/en/docs/stream/ngx_stream_ssl_module.html
[nginx-install]: https://nginx.org/en/linux_packages.html
[certbot-install]: https://certbot.eff.org/instructions
[ip-certificates]: https://letsencrypt.org/2026/03/11/shorter-certs-certbot
[certbot-commands]: https://eff-certbot.readthedocs.io/en/stable/using.html#certbot-commands
[certbot-renewal]: https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates

# Mount a Drive over WebDAV

A homeserver exposes every user's drive as a WebDAV share, so a Pubky drive can be
mounted in a normal file manager and used like any other network folder. Files
written there are the same files the REST storage API serves.

## Contents

- [In a Browser](#in-a-browser)
  - [The Built-in Explorer](#the-built-in-explorer) | [Third-party Clients](#third-party-web-clients)
- [The Endpoint](#the-endpoint)
- [Getting Credentials](#getting-credentials)
  - [Demo Users](#demo-users-test-homeservers)
- [Connect from Ubuntu](#connect-from-ubuntu-gnome-files)
- [Connect from macOS](#connect-from-macos-finder)
- [Connect from the Command Line](#connect-from-the-command-line)
- [Put It Behind TLS](#put-it-behind-tls)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)

## In a Browser

Two routes to a browser view: the explorer the homeserver ships, or any third-party
web client.

### The Built-in Explorer

The homeserver serves a file explorer at **`/drive`**. Sign in with a public key
and token and you get a Drive-style view of the same files: folders, image
thumbnails, text preview, upload, delete and download.

```
http://<homeserver>:6286/drive?user=<public-key>
```

The `user` parameter just prefills the key, so a link only needs the token typed.
This is the URL to hand someone who wants to look around before mounting anything.

The page is one static asset with no state of its own: every listing, read and write
is a WebDAV request authorized by the user's own token, held in `sessionStorage` for
that tab only. Because it is served by the homeserver, its requests are same-origin
and work on a homeserver that is not reachable from the public internet.

### Third-party Web Clients

`/dav` answers CORS preflights, so browser-based WebDAV clients work against it
directly. Point one at the same URL a file manager would use, with the public key as
username and the token as password.

[Filestash](https://www.filestash.app/webdav-client.html) is the most convenient:
it proxies server-side, so it works even from a hosted instance. Self-hosting it
takes one container plus enabling the WebDAV backend:

```bash
docker run -d --name filestash -p 8334:8334 machines/filestash

# The login page only offers backends listed in the config.
docker exec filestash sh -c 'cat > /app/data/state/config/config.json <<JSON
{ "general": { "secret_key": "change-me" },
  "connections": [ { "type": "webdav", "label": "Pubky Drive" } ] }
JSON
chown filestash:filestash /app/data/state/config/config.json'
docker restart filestash
```

Then open `http://localhost:8334` and sign in with the WebDAV URL, public key and
token.

> A third-party client — hosted or self-hosted — sees the token and the file
> contents in the clear. That is a fair trade for a throwaway demo account and a bad
> one for a real drive. The built-in explorer avoids it.

### How Both Work

CORS and WebDAV disagree about `OPTIONS`, and `/dav` handles the two cases
separately:

| Request | Answered by | Why |
|---|---|---|
| `OPTIONS` with `Access-Control-Request-Method` | The CORS middleware, before auth | A browser strips credentials from a preflight, so requiring auth would 401 it |
| `OPTIONS` without it | `dav-server` | It is a WebDAV capability probe, and only the handler knows the `DAV:` header a file manager reads before mounting |

A blanket CORS layer answers *every* `OPTIONS` itself, which silently removes the
`DAV:` header and stops Finder and GNOME Files mounting at all. That is why `/dav`
sits outside the server's general CORS layer and has its own.

Cross-origin requests are allowed from any origin but **never with credentials**.
Browsers will not attach cookies under those terms, so the `SameSite=None` session
cookie cannot be used to read a drive from another site; a browser client
authenticates with an `Authorization` header it must already hold.

## The Endpoint

```
http://<homeserver>:6286/dav/<public-key>/
```

The path segment after `/dav/` is the drive's owner, in z-base32. It must match the
user the credentials belong to — a session can only ever reach its own drive.

Authenticate one of two ways:

| Scheme | Header | Used by |
|---|---|---|
| Basic | `Authorization: Basic base64(<public-key>:<token>)` | File managers, `rclone`, `curl -u` |
| Bearer | `Authorization: Bearer <token>` | The Pubky SDK |

Basic auth exists because file managers speak nothing else. The username is the
user's public key and the password is the session token. Identity comes from the
token, so the username is only there to keep clients happy.

The endpoint reports `DAV: 1,2,3` and supports `PROPFIND`, `GET`, `PUT`, `DELETE`,
`MKCOL`, `COPY`, `MOVE`, `LOCK` and `UNLOCK`.

## Getting Credentials

A WebDAV client cannot run the [Pubky Ring](https://github.com/pubky/pubky-ring)
signing flow, so it needs a token it can send verbatim. Any session token works,
but ordinary ones expire after an hour — long enough to try a mount, not to keep
one. For a persistent mount you want a long-lived token.

### Demo Users (Test Homeservers)

On a homeserver run for people to try things out, the admin API can provision a
throwaway identity, seed it with a small drive worth browsing, and issue a long-lived
token in one call:

```bash
curl -s -X POST "http://127.0.0.1:6288/generate_demo_user" \
  -H "X-Admin-Password: $ADMIN_PASSWORD"
```

```json
{
  "public_key": "xizq71oidk6os1ryb9xpca7kdjxpn3yxskrbtp5r7u398p9ewcbo",
  "secret_key": "2b7177b9d6e93354c0b922ff2c52887ee8cca0b8db0d9a102b8c240860d461d6",
  "token": "hDdAyy-EKZ_RBkH54fOBCaF8qrCTUd95XNxEtOWO3pY",
  "grant_id": "N8FU75aspOcgvATbalIRog",
  "expires_at": 1819989379,
  "basic_auth": "Basic eGl6cTcxb2lkazZvczFyeWI5eHBjYTdrZGp4cG4z…",
  "webdav_url": "http://localhost:6286/dav/xizq71oidk6os1ryb9xpca7kdjxpn3yxskrbtp5r7u398p9ewcbo/",
  "drive_url": "http://localhost:6286/drive?user=xizq71oidk6os1ryb9xpca7kdjxpn3yxskrbtp5r7u398p9ewcbo",
  "seeded_files": ["/pub/README.txt", "/pub/index.html", "/pub/photos/harbour.png", "…"]
}
```

Hand a user the `drive_url` if you just want them to look around in a browser, or
the `public_key` (their username), `token` (their password) and `webdav_url` if they
are mounting it. The `secret_key` is the identity itself, returned once and never
stored, so they can keep using it with the SDK afterwards.

The seeded drive spans both roots, so there is something to navigate on either side
of the public/private line:

```
pub/                                priv/
├── README.txt                      └── drive/
├── index.html                          ├── documents/
└── photos/                             │   ├── expenses.csv
    ├── harbour.png                     │   ├── reading-list.md
    ├── orchard.png                     │   └── welcome.md
    ├── ridge.png                       ├── photos/scan-0001.png
    └── captions.txt                    └── projects/pubky-demo/
```

`pub/index.html` is worth pointing out: it is a real web page, live at
`<homeserver>/storage/<public-key>/pub/index.html` with no credentials, editable
from the mounted folder.

Optional query parameters:

| Parameter | Default | Meaning |
|---|---|---|
| `capabilities` | `/:rw` | Capability string granted to the token |
| `client_id` | `demo.webdav` | Recorded on the grant, so demo grants are easy to spot |
| `lifetime_days` | `365` | Token lifetime |
| `seed` | `true` | Whether to write the sample files |

Revoke one later with `DELETE /auth/grant/session/{grant_id}`, authenticated with that
user's own token.

> **This is a demo tool.** It creates users without a signup token and hands out
> long-lived credentials, so it is gated only by the admin password. Keep the admin
> port off the public internet. It also means the server generates the identity, so
> it briefly holds a secret key that ought to be the user's alone — fine for a
> throwaway test account, not for a real one.

## Connect from Ubuntu (GNOME Files)

GNOME Files (Nautilus) has WebDAV support built in through GVfs.

1. Open **Files**.
2. Click **Other Locations** in the sidebar.
3. In **Connect to Server** at the bottom, enter the address using the `dav://`
   scheme (or `davs://` for HTTPS):

   ```
   dav://<homeserver>:6286/dav/<public-key>/
   ```

4. Click **Connect**. A dialog asks for credentials against the realm `pubky`.
5. Choose **Registered User** and fill in:
   - **Username**: the public key
   - **Password**: the token
   - Leave **Domain** as it is.
6. Tick **Remember password** to keep the mount across sessions, then **Connect**.

The drive appears in the sidebar with a `pub/` folder inside. Drag files in and out
as normal. It is also a real path on disk, under
`/run/user/$UID/gvfs/dav:host=…`, so ordinary tools work on it too.

To disconnect, click the eject icon next to the mount.

## Connect from macOS (Finder)

Finder speaks WebDAV natively.

1. In Finder, choose **Go → Connect to Server** (**⌘K**).
2. Enter the address, using the `http://` (or `https://`) scheme rather than `dav://`:

   ```
   http://<homeserver>:6286/dav/<public-key>/
   ```

3. Click **Connect**. Finder asks how to connect.
4. Choose **Registered User** and fill in:
   - **Name**: the public key
   - **Password**: the token
5. Tick **Remember this password in my keychain** to keep the mount, then **Connect**.

The drive mounts under `/Volumes` and appears in the Finder sidebar. Eject it as you
would any network volume.

Finder stores the credentials in Keychain. If the token is later revoked or expires,
Finder keeps sending the stale one and the mount fails without re-prompting — open
**Keychain Access**, delete the entry for the homeserver's host, and reconnect.

## Connect from the Command Line

```bash
# Everything below assumes these
HS="http://127.0.0.1:6286"
KEY="<public-key>"
TOKEN="<token>"

# List a directory
curl -u "$KEY:$TOKEN" -X PROPFIND -H "Depth: 1" "$HS/dav/$KEY/pub/"

# Upload and download
curl -u "$KEY:$TOKEN" -T ./local.txt "$HS/dav/$KEY/pub/local.txt"
curl -u "$KEY:$TOKEN" "$HS/dav/$KEY/pub/local.txt"

# Create a directory, then delete it
curl -u "$KEY:$TOKEN" -X MKCOL "$HS/dav/$KEY/pub/notes/"
curl -u "$KEY:$TOKEN" -X DELETE "$HS/dav/$KEY/pub/notes/"
```

`rclone` works too, and is the easier option for bulk transfers:

```bash
# `rclone obscure` is required — rclone reads the `pass` value as an obscured
# string, and a plaintext token there fails with 401.
rclone config create pubky webdav \
  url "$HS/dav/$KEY/" vendor other user "$KEY" pass "$(rclone obscure "$TOKEN")"

rclone ls pubky:pub
rclone copy ./local.txt pubky:pub/notes/
```

## Put It Behind TLS

**Basic auth sends the token in a base64 header, which is encoding, not encryption.**
Anyone on the path can read it from a plain HTTP request. Use `http://` only against
`127.0.0.1` or a trusted LAN.

For anything reachable from the internet, terminate TLS in front of port 6286 and
give users an `https://` address — see [DEPLOY.md](./DEPLOY.md). The Pubky TLS port
(6287) is not an alternative here: it authenticates with a raw public key rather
than a CA-issued certificate, which no file manager will accept.

## Limitations

- **Access within a drive is all-or-nothing.** Any session that authenticates
  reaches the whole drive over WebDAV. Capability scopes and the `/pub/` + `/priv/`
  write-root rule that the REST routes enforce do not apply here, because clients
  mount and `PROPFIND` the drive root, which no scoped capability covers. Per-user
  `allowed_write_paths` and write-collision checks do still apply. Treat a WebDAV
  token as full access to that one drive.
- **Locks are advisory only.** `LOCK` and `UNLOCK` answer correctly — macOS needs
  them to mount writable — but nothing is actually locked, so simultaneous writers
  can overwrite one another.
- **No quota or rate limiting** is applied on this endpoint yet.
- **File managers leave junk.** Finder writes `.DS_Store` and `._` files, GNOME
  writes `.Trash-$UID`. These are accepted, including at the drive root outside
  `/pub/` and `/priv/`, where the REST API would reject them.

## Troubleshooting

**The client refuses to mount, or reports "not a WebDAV server".**
Check that `OPTIONS` advertises DAV compliance:

```bash
curl -i -u "$KEY:$TOKEN" -X OPTIONS "$HS/dav/$KEY/"
```

The response must carry a `DAV: 1,2,3,…` header. A bare `200 OK` without it means
something in front of the homeserver — a CORS layer or a reverse proxy — is
answering `OPTIONS` itself.

**403 Forbidden on every request.**
The public key in the URL does not match the credentials. A session only ever
reaches its owner's drive, so `/dav/<someone-else>/` is always a 403, and so is any
path that resolves into another drive via `..`.

**401 Unauthorized even though the token looks right.**
The token has expired or been revoked. Mint a new one and update the saved
credential — macOS Keychain and the GNOME keyring both cache the old one.

**GNOME says "Operation not supported".**
The GVfs WebDAV backend is missing: `sudo apt install gvfs-backends`.

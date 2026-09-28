# Mount a Public Folder over WebDAV

A homeserver exposes every user's public folder as a read-only WebDAV share, so
anyone can open a `/pub/` in a normal file manager — no account, no credentials.
The files are the same ones the REST storage API serves at
`/storage/<public-key>/pub/`.

*For what comes next — writes, private folders, mounting your own drive — see
[WEBDAV-FOLLOWUP.md](./WEBDAV-FOLLOWUP.md).*

## The Endpoint

```
http://<homeserver>:6286/dav/<public-key>/pub/
```

The path segment after `/dav/` is the drive's owner, in z-base32. `/pub/` is the
only folder that exists here.

Nothing is authenticated. Anything under `/pub/` is world-readable over the REST
API already, and the endpoint serves exactly that and nothing more:

- **Only `GET`, `HEAD`, `OPTIONS` and `PROPFIND` are served.** Anything that
  would write gets `405` with an `Allow` header, which is what a file manager
  reads to mount the share read-only rather than report it broken.
- **Only `/pub/` exists.** The drive root, `/priv/` and everything else are
  `404` — not `401` or `403`, which would confirm there is something there.

`OPTIONS` reports `DAV: 1` — compliance class 1, no locking — with an `Allow`
that lists only the read verbs, and a write attempt gets `405`. Between them
that is what a file manager needs to mount the share read-only rather than
report it broken.

Bandwidth quotas and request rate limits apply as they do to the REST routes.
The shipped config also rate-limits `PROPFIND` per IP, generously enough for a
real sync client.

## Connect from Ubuntu (GNOME Files)

1. Open **Files**, then **Other Locations** in the sidebar.
2. In **Connect to Server**, enter the address with the `dav://` scheme (or
   `davs://` for HTTPS):

   ```
   dav://<homeserver>:6286/dav/<public-key>/pub/
   ```

3. Click **Connect**. If a credentials dialog appears, choose **Anonymous**.

The folder appears in the sidebar. It is also a real path under
`/run/user/$UID/gvfs/dav:host=…`, so ordinary tools work on it. Click the eject
icon to disconnect.

## Connect from macOS (Finder)

1. **Go → Connect to Server** (**⌘K**).
2. Enter the address with the `http://` (or `https://`) scheme:

   ```
   http://<homeserver>:6286/dav/<public-key>/pub/
   ```

3. Click **Connect** and choose **Guest**.

The folder mounts read-only under `/Volumes`. Eject it like any network volume.

## Connect from the Command Line

```bash
HS="http://127.0.0.1:6286"
KEY="<public-key>"

# List a directory
curl -X PROPFIND -H "Depth: 1" "$HS/dav/$KEY/pub/"

# Download a file
curl -O "$HS/dav/$KEY/pub/notes/hello.txt"

# Bulk download with rclone
rclone config create pubky webdav url "$HS/dav/$KEY/pub/" vendor other
rclone copy pubky:notes ./notes
```

## In a Browser

A folder URL shows a plain directory listing; a file URL serves the file with
its stored content type. `/dav` answers CORS preflights for any origin, so
browser-based WebDAV clients work against it directly with no username or
password.

## Clients

Any WebDAV client should be able to read the share — anonymous read-only is the
simplest case the protocol has. Verified: `curl` and the server's integration
tests, which drive the mount sequence and the refusals. Expected but not yet
driven through the GUI: GNOME Files, Finder, Dolphin, `rclone`, Cyberduck,
Windows Explorer. `rsync` and the Nextcloud/ownCloud desktop clients are not
WebDAV clients and will not work.

## TLS

There are no credentials to leak, but file contents travel in the clear over
`http://`. For anything reachable from the internet, terminate TLS in front of
port 6286 — see [DEPLOY.md](./DEPLOY.md). The Pubky TLS port (6287) is not an
alternative: it authenticates with a raw public key, which no file manager will
accept.

## For Operators

Confinement is by storage key, not by what the key resolves to on disk. On the
filesystem backend a symlink placed inside `data/files/<key>/pub/` is followed,
so one pointing at `../priv` would serve private files. Only someone with
access to the data directory can create one — no client can — and REST would
not serve it, since it has no entry. Keep symlinks out of the data directory.

## Limitations

- **Read-only, public folders only.** You cannot yet mount your own drive to
  write to it, or reach `/priv/`.
- **The URL must end in `/pub/`.** The drive root is `404` by design.
- **`PROPFIND` needs `Depth: 0` or `1`.** `Depth: infinity` is refused with
  `501`, so listing a whole subtree is one request per directory; a request
  with no `Depth` header is served as a one-level listing. File managers
  already work this way; sync tools that fetch a tree in one call will not.
- **Content types are guessed from the file name.** REST serves the type a
  file was stored with; WebDAV serves what the extension suggests, so a file
  with no extension is `application/octet-stream` whatever it holds.
- **No free-space figure** for clients that show disk usage.

## Troubleshooting

**"Not a WebDAV server."** `curl -i -X OPTIONS "$HS/dav/$KEY/pub/"` must return a
`DAV: 1` header. A bare `200 OK` without it means something in front of the
homeserver — a reverse proxy or a CORS layer — is answering `OPTIONS` itself.

**404 on everything.** The URL does not end in `/pub/`, or the key is
misspelled. The drive root and `/priv/` are `404` deliberately.

**405 Method Not Allowed.** The client tried to write. The share is read-only.

**GNOME says "Operation not supported".** `sudo apt install gvfs-backends`.

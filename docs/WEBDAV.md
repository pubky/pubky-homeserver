# WebDAV

A homeserver can serve each user's public folder as a read-only WebDAV share:

```text
https://<homeserver>/dav/<user-key>/pub/
```

The share holds the same files as `/storage/<user-key>/pub/`. Anyone can read
and list them without signing in, from a file manager, a sync tool such as
rclone, or a browser.

The share is off by default. Turn it on with `[drive] webdav_enabled = true`.
`/info` doesn't list it, so a client can't discover whether a homeserver
serves it.

The admin server has a separate, read-write `/dav` share of every drive behind
the admin password. See the [Admin API](../pubky-homeserver/openapi-admin.yml).

## What the share serves

- Only `/pub/` and the paths inside it. Any other path under a user, including
  the drive root and `/priv/`, returns `404`.
- A path that names no user, or that climbs out of the user's drive with `..`,
  returns `400`.
- The share ignores sessions. A signed-in owner sees the same files as everyone
  else.

## Methods

| Method | Result |
| --- | --- |
| `OPTIONS` | `DAV: 1` and the methods the path takes in `Allow`. Answered for any path under a valid user. |
| `GET`, `HEAD` | A file. Range and conditional requests are supported. |
| `PROPFIND` | A file's properties, or a folder listing. |
| Other WebDAV methods | `405` with `Allow: OPTIONS, GET, HEAD, PROPFIND`. |
| Unknown methods | `501`. |

- A folder has no index page. `GET` or `HEAD` on a folder returns `405` with
  `Allow: OPTIONS, PROPFIND`.
- `PROPFIND` lists one level. A request without `Depth` is treated as
  `Depth: 1`, and `Depth: infinity` returns `501`.
- `DAV: 1` means the share takes no locks, which is how a file manager knows to
  mount it read-only.

## Differences from `/storage`

- The content type is guessed from the file name's extension, not the one
  stored at upload. A file without an extension is served as
  `application/octet-stream`.
- Range requests work on `/dav`.
- `/dav` never lists a folder in response to `GET`.

## Browsers

Every response allows any origin and never allows credentials, so a web app can
read the share with `fetch` but can't send the session cookie. A CORS preflight
is answered with `204` and allows whichever request headers it asks for.

## Rate limits

Path rate limits match the storage path a request reads, as they do for
`/storage`. A rule for `/pub/**` covers the same files on both routes, and a
`/dav/<user-key>/pub/a%20b` request matches `/pub/a b`.

No limit on `PROPFIND` ships by default. One `PROPFIND` lists a whole folder,
however large, so add a limit when you turn the share on:

```toml
[[drive.rate_limits]]
path = "/pub/**"
method = "PROPFIND"
quota = "30r/m"
key = "ip"
```

The bandwidth limits in `[default_quotas]` also apply. A client's read
allowance on `/dav` is counted separately from its allowance on `/storage`.

## Limitations

- Folder listings aren't capped or paginated.
- Under a [website](WEBSITES.md) `Host`, `/dav/...` reaches the share, not the
  site, so a site can't use `dav` as a top-level folder.

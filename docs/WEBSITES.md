# Websites

A homeserver serves each user's static websites from their public storage,
selected by the request's `Host`:

| `Host` | Site folder |
| --- | --- |
| `<user-key>` | `/pub/website/_/` |
| `<label>.<user-key>` | `/pub/website/<label>/` |

Upload a site with the normal storage API, for example
`PUT /storage/<user-key>/pub/website/_/index.html`. The files stay ordinary
public storage, so they move with the user to another homeserver.

`/info` lists the `websites` feature when the homeserver serves sites.
Operators can turn it off with `[drive] websites = false`.

## Hosts

- A label uses letters, digits and inner hyphens, at most 63 characters.
  Hosts are case-insensitive, so folder names must be lowercase:
  `Blog.<user-key>` serves `/pub/website/blog/`.
- The port and a trailing dot are ignored.
- `_pubky.<user-key>`, the homeserver's own key, deeper names such as
  `a.b.<user-key>`, and other hosts are not websites. They keep the client
  API behavior.
- The owner comes from `Host` alone; `pubky-host` is ignored.

## Paths that stay on the API

Only GET and HEAD reach a site. Requests whose first path segment is `auth`,
`events`, `events-stream`, `info`, `priv`, `pub`, `session`, `signup`,
`signup_tokens` or `storage` go to the client API as before, so a site cannot
use these as top-level folders. Nested folders such as `/blog/pub/` are fine.

## Responses

- `/` and folder paths serve the folder's `index.html`. Folders are never
  listed.
- `/docs` redirects with `301` to `/docs/`, keeping the query string, when
  `docs/index.html` exists and there is no file `docs`.
- A missing file returns `404`, with the site's `404.html` as the body when it
  exists. A missing file never falls back to another site.
- HEAD returns the same status and headers as GET without a body. Both answer
  `If-None-Match` and `If-Modified-Since` with `304`.
- Every response has `Cache-Control: no-cache` and
  `X-Content-Type-Options: nosniff`. Content types are the ones stored at
  upload.
- An unknown user returns `404` and a disabled user `403`.
- Path rate limits match the site file's storage path, so a
  `/pub/website/**` rule applies to website requests. A folder request matches
  the folder's `index.html`, so a rule for `/pub/website/_/index.html` also
  limits `/`. Website requests are not counted in the
  [storage-addressing metric](STORAGE_ADDRESSING_MIGRATION.md).

## Limitations

- Range requests are not supported, so Safari cannot play `<video>` from a
  site.
- Browsers reach `<user-key>` hosts only with Pkarr routing and TLS for the
  user's key, which the homeserver does not provide yet.

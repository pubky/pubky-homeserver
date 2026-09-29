# WebDAV: read-only public folders first, writable drives next

*Issue text. The read-only endpoint is documented for users in
[WEBDAV.md](./WEBDAV.md).*

## Why `dav-server` over `OpendalFs`

Two routes were weighed for the client endpoint: `dav-server` with the stock
`OpendalFs` (the admin server's approach), or `dav-server` with a custom
`DavFileSystem` over `FileService`. Writes were exercised under the first,
and every problem found turned out to belong in the OpenDAL layer stack, not
in the filesystem behind `dav-server`:

- `COPY`/`MOVE` bypassing the database belongs in `WriteFinalizationLayer`,
  which also covers the admin operator. A custom filesystem would need the
  same bookkeeping, for WebDAV alone.
- Directory `DELETE` does not orphan entries: `dav-server` recurses file by
  file, each through the finalization deleter.
- Lock keep-alive through a long upload has no lock token in either route.

What `OpendalFs` genuinely cannot express is small — `get_quota` for
free-space display, and mapping a quota refusal to `507` rather than `500` —
and both fit in a thin `DavFileSystem` wrapper that delegates everything else.
That wrapper is the escape hatch if more control is ever needed; a rewrite of
the eight filesystem methods and a streaming `DavFile` is not warranted.

## One endpoint for both servers

`shared::webdav::endpoint::DavEndpoint` now owns what the admin and client
endpoints must agree on: the `dav-server` handler, the verb policy
(`DavAccess::{ReadOnly, ReadWrite}`, with `405` + `Allow` otherwise), and the
`OPTIONS` handling that tells a CORS preflight from a WebDAV capability probe.
Each server keeps its own policy at the edge and hands the endpoint an operator
already scoped to what the caller may see:

| | admin | client |
|---|---|---|
| auth | Basic `admin:<password>`, in the handler | none (stage 1); session (stage 2) |
| operator | `admin_operator`, every drive | app operator + `TenantScopeLayer` |
| access | `ReadWrite`, `FakeLs` | `ReadOnly` |

Stage 2 converges the rest: both become *authenticate → scope an operator →
`DavEndpoint`*, and a real lock system replaces `FakeLs` in one place for both.
Neither endpoint has its own switch: the client one is always on, since it
exposes nothing `/storage` does not already, and the admin one comes and goes
with the whole admin server.

## Stage 1 — this branch

Anyone can mount `/dav/{key}/pub/` read-only, no credentials. `/pub/` is
world-readable over REST already; this serves exactly that.

- `GET`, `HEAD`, `OPTIONS`, `PROPFIND` only. The drive root and `/priv/` are
  `404`, never `401`/`403`, so nothing confirms they exist.
- No directory index: a `GET` on a folder is `405`. dav-server's autoindex
  lists a folder exactly as `PROPFIND` does, one stat per entry, but through
  a verb the PROPFIND rate limit never sees. The admin share keeps it.
- Confinement enforced twice: `DavTarget` canonicalizes the path and checks
  `/pub/`; `TenantScopeLayer::public` refuses anything else at the storage
  boundary, per request.
- `DavEndpoint` shared with the admin server, as above. Moving the admin `/dav`
  out from under `CorsLayer::very_permissive()` fixed a bug on `main`: the
  layer answered every `OPTIONS` itself, so the admin share never sent `DAV:`
  and no file manager could have mounted it.
- `PROPFIND` rate-limited 600/min per IP. The shipped glob was `/dav/*`, which
  `fast-glob` never matches past a `/`; it is now `/dav/**`, with a test.
- `webdav` label on the storage request counter. No config flag: the
  endpoint exposes nothing `/storage` does not already, and no other client
  route has one.

Not yet done:

- A real GNOME Files or Finder mount driven through the GUI.
- **ETags.** `dav-server` emits `ETag`/`getetag` and honours `If-None-Match`,
  `If-Match` and `If-Range`, all from `DavMetaData::etag()`, whose default
  derives `<len>-<mtime>`. `dav-server-opendalfs` overrides it to return only
  what the backend reports, and the `fs` and memory backends report nothing —
  so the share sends no ETag at all, `If-None-Match` is always `200`, and a
  sync client such as rclone re-downloads everything on every pass. Fix: fall
  back to the default derivation in the thin `DavFileSystem` wrapper (stage 2
  below), where `metadata` and `read_dir` already need wrapping. Until then
  `EXPOSE_HEADERS` names an `etag` that never appears.

## Stage 2 — authenticated, writable drives

- [ ] **Basic auth on `/dav` only**, key as username, token as password —
      file managers speak nothing else. Widening `extract_bearer_token`
      globally broke `/events-stream` cookie fallback; do it as a layer on the
      dav router. Long-lived tokens for these clients are a separate decision.
- [ ] **Per-path authorization** with `has_read_permission` /
      `has_write_permission`; `COPY`/`MOVE` authorize `Destination` separately;
      unknown verbs fail closed. Scoped tokens still need to list the drive root
      and the two storage roots to mount.
- [ ] **`403` outside `/pub/` and `/priv/`** (Finder's `.DS_Store` at the root).
- [ ] **Upload cap** via `RequestBodyLimitLayer` — the handler streams the raw
      request, so `DefaultBodyLimit` does nothing.
- [ ] **`copy` and `rename` in `WriteFinalizationLayer`**, following the write
      path's ordering — lock users, check collisions and quota, commit the
      backend, then entries, events and usage in one transaction. Without it a
      rename in a file manager makes the file unreachable over REST at both
      names, and copies escape quota. `rename` must handle a whole directory;
      `dav-server` renames a collection in one call.
- [ ] **Thin `DavFileSystem` wrapper**: `get_quota` from `used_bytes`;
      `RateLimited` → `InsufficientStorage` so over-quota is `507`; and a cap
      on `read_dir`. Today a `PROPFIND` costs one list plus one stat per entry
      with nothing bounding the entry count — the per-IP limit bounds requests,
      not directory size, and a user controls how many files sit in one folder.
      Either cap it or serve listings from the database, paginated, as REST does.
- [ ] **Locks.** macOS needs the `LOCK` handshake to mount writable. Either
      `FakeLs` first, documented as advisory, or a `DavLockSystem` on
      `entry_locks` (#630) so REST and WebDAV locks see each other. The table
      needs subtree queries and `owner`/`principal` columns for that, and a
      long upload can outlive a 60s lock either way.
- [ ] **`MKCOL`**: decide whether an empty directory gets an entry. Today it
      exists in storage only, invisible to REST and the event feed.
- [ ] Converge the admin endpoint onto the same auth → scope → endpoint path.
- [ ] **One `PathGuardLayer` behind `WritePathLayer` and `TenantScopeLayer`.**
      They are the same layer asking a different question of each path: ~80
      lines of identical accessor-plus-deleter delegation apiece, differing
      only in the predicate (a DB lookup of `allowed_write_paths` vs a string
      prefix check), which operations are guarded (mutations vs everything)
      and the error raised. A generic layer over a small `PathPolicy` trait —
      `check_read` defaulting to allow, `check_write` required — turns each
      into a ~15-line policy behind a type alias, with no call-site or test
      changes. Two mechanical details from a first attempt: the policy needs
      an `Unpin` bound (`Access` and `oio::Delete` require it), and the alias
      must not define its own `new` alongside the generic's. Its own small PR,
      since it touches `WritePathLayer` on main.

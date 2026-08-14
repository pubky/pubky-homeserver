# Private Storage in the Client API

The access rules in this document apply to the homeserver Client API. The Admin
API has separate authorization rules: a homeserver administrator can read and
write all tenant data, including data under `/priv/`.

## Storage namespaces

| Root | Read access | Write access |
| --- | --- | --- |
| `/pub/` | Public | Matching session with a write capability |
| `/priv/` | Matching session with a read capability | Matching session with a write capability |

The session user must match the storage owner. A `pubky://` URL identifies the
owner and path.

```text
pubky://<user>/pub/my-app/profile.json     # public
pubky://<user>/priv/my-app/settings.json  # authenticated
```

JavaScript SDK example for a session with `/priv/my-app/:rw`:

```js
const path = "/priv/my-app/settings.json";
await session.storage.putJson(path, { theme: "dark" });
const settings = await session.storage.getJson(path);
```

## Capabilities

Capabilities use the format `<scope>:<actions>`, where the actions are `r`, `w`,
or `rw`.

| Capability | Access |
| --- | --- |
| `/priv/my-app/:r` | Read the directory and its descendants |
| `/priv/my-app/settings.json:rw` | Read and write one file |
| `/:rw` | Read and write all valid storage paths |

A trailing `/` defines a directory scope. Without it, the scope matches only the
exact file path.

## Events

`GET /events/` returns public events only. `GET /events-stream` defaults to a
`/pub/` path filter when `path` is omitted.

Public stream:

```http
GET /events-stream?user=<user>&path=/pub/my-app/&live=true
```

Private stream:

```http
GET /events-stream?user=<user>&path=/priv/my-app/&live=true
Authorization: Bearer <session-token>
```

A private stream requires exactly one `user`, matching the session user, and a
read capability covering every private path filter. Repeated `path` parameters
form a union:

```http
GET /events-stream?user=<user>&path=/pub/my-app/&path=/priv/my-app/
Authorization: Bearer <session-token>
```

If a Bearer header is present, cookie authentication is not considered. The
legacy tenant-cookie fallback applies only to private, single-user streams sent
directly to a homeserver. The admin event stream can include private events.

### Path filters

| Input | Normalized filter |
| --- | --- |
| `priv//my-app/./data/` | `/priv/my-app/data/` |
| `/priv/my-app/../settings.json` | `/priv/settings.json` |
| `/../../priv/` | Rejected |

A trailing `/` matches a directory subtree; otherwise the filter matches one
file.

## Existing data

`/priv/` is a separate namespace. Existing `/pub/` data is not moved.

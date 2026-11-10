# Parent and child grants

A parent grant lets one trusted holder, such as Pubky Accounts, sign in
first-party apps without asking the user to approve each one in Ring. This guide
is for developers who build Accounts, Ring and SDK integrations. It covers the
token format, the homeserver API and the grant lifecycle.

Existing direct grants don't change. Check that `GET /info` lists
`grant-delegation` before you use this API. Older homeservers reject the new
token types.

## Tokens

All tokens are Ed25519 JWS values with `alg: EdDSA`.

| Token | `typ` | Signed by | Can do |
| --- | --- | --- | --- |
| Direct grant | `pubky-grant` | The user's identity key | Create storage sessions |
| Parent grant | `pubky-parent-grant` | The user's identity key | Authorize child grants |
| Child grant | `pubky-child-grant` | The key in the parent's `cnf` | Create storage sessions |

A chain has two levels: a parent can sign many children, and a child can't sign
further grants. A parent can't create storage sessions.

Decoded parent, signed by `<user-key>`:

```json
{
  "iss": "<user-key>",
  "client_id": "https://accounts.example/auth/callback",
  "caps": ["/pub/:rwe", "/priv/:rwe"],
  "cnf": "<accounts-key>",
  "jti": "parent_a",
  "iat": 1793664000,
  "exp": 1856736000
}
```

Decoded child, signed by `<accounts-key>`:

```json
{
  "iss": "<user-key>",
  "client_id": "https://chat.example/auth/callback",
  "caps": ["/pub/chat/v1/:rw", "/priv/chat/v1/:rwe"],
  "cnf": "<chat-key>",
  "jti": "chat_a",
  "parent_jti": "parent_a",
  "iat": 1793664100,
  "exp": 1856736000
}
```

The homeserver accepts a chain only when all of these are true:

- The user's key signed the parent, and the parent's `cnf` key signed the child.
- `child.iss` equals `parent.iss`, and `child.parent_jti` equals `parent.jti`.
- `parent.iat <= child.iat < child.exp <= parent.exp`.
- Neither grant has expired, and neither `iat` is more than three minutes ahead.
- The parent stays within `/pub/:rwe` and `/priv/:rwe`, so it can't grant `/:rw`.
- Each child scope and action is within the parent, compared by path rather than
  by string prefix.
- Both `client_id` values are exact HTTPS callback URLs in canonical form. They
  can't contain credentials or a fragment.

The `e` action only covers encryption keys. It gives no storage access. The
homeserver doesn't look up an app catalog: Accounts decides which apps and
permissions to allow within the parent's limit.

## App identity

Accounts must use each app's fixed, registered HTTPS callback in canonical form
as `client_id` for child grants and reconnect proofs. Before signing, it must
verify that callbacks from requests or redirecting pages match the registration
and pending sign-in flow exactly, with no wildcards or prefix matching. Keep
navigation destinations in separate, single-use sign-in state.

The homeserver keys app replacement and blocks on the exact callback. Canonical
URLs with different paths (such as `/cb` and `/cb/`), query strings or non-default
ports remain distinct identities. Signing a variant for the same app can bypass
its block.

## Exchange a child grant for a session

Send the parent, the child and a proof-of-possession (PoP) signed by the child's
`cnf` key to `POST /auth/grant/session`. The PoP's `gid` is the child's `jti`.

```json
{
  "parent": "<parent JWS>",
  "grant": "<child JWS>",
  "pop": "<PoP JWS>"
}
```

The response has the same format as a direct grant exchange, with the child's
identity, capabilities and grant ID. The bearer lasts at most one hour and never
outlives the child or the parent.

| Status | Meaning |
| --- | --- |
| `400` | The format, grant type, parent reference, timestamps or callback is invalid |
| `401` | A signature or PoP is invalid, a nonce was replayed, or a grant has expired or been revoked |
| `403` | The capabilities exceed the limit, the app is blocked and must be reconnected, or a grant ID is already stored for another user or with different claims |
| `404` | The user doesn't exist on this homeserver |

`POST /auth/grant/signup` accepts direct grants only.

## One active child per app

Each `(user, parent, app callback)` has at most one active child. Devices with
separate parents don't affect each other.

- The first exchange of a new child records it, revokes the app's previous child
  and deletes that child's sessions.
- Repeating the exchange of the active child only replaces its bearer.
- A revoked or replaced child never becomes active again.
- A grant ID always refers to the same claims. Reusing an ID with any changed
  claim returns `403`. This also applies to direct grants.

## Revoke grants

The operation you use states your intent, so the effects differ.

| Operation | Request | Effect |
| --- | --- | --- |
| App signs out | `DELETE /auth/grant/session` with the child's bearer, or with `parent`, `grant` and `pop` from the child's key | Revokes the child and its sessions. The parent and other apps keep working, and a new child can sign in. |
| User removes an app | `DELETE /auth/grant/session/{gid}` with the child's ID and a root session | Revokes the app's current child and sessions, and blocks the app under that parent. |
| Accounts signs out | `DELETE /auth/grant/session` with the parent JWS in `grant` and `pop` from the parent's key | Revokes the parent and all its children, and deletes their sessions. |
| User removes a parent | `DELETE /auth/grant/session/{gid}` with the parent's ID and a root session | Same as Accounts signing out. |

Revoking a parent also stops children that were never exchanged. Other parents
aren't affected. To sign in again after that, the user needs a new parent from
Ring.

Proof-based signout works after a grant expires and can be retried with a fresh
nonce. It also works before first use: an unseen parent or child is recorded as
revoked, without replacing the app's current child.

Revocation closes the private event streams of every affected child, across
homeserver instances. A child's bearer stops working as soon as the child or its
parent is revoked, or its app is blocked.

## Reconnect a blocked app

After the user removes an app, its exchanges return `403` until Accounts clears
the block. Ask the user to confirm in Accounts first, then call
`POST /auth/grant/reconnect`:

```json
{
  "parent": "<parent JWS>",
  "proof": "<reconnect proof JWS>"
}
```

The proof has `typ: pubky-reconnect` and is signed by the parent's `cnf` key. An
ordinary PoP or a child's key can't authorize it.

```json
{
  "aud": "<homeserver-key>",
  "gid": "parent_a",
  "nonce": "<random nonce>",
  "iat": 1793665000,
  "client_id": "https://chat.example/auth/callback"
}
```

A successful call returns `204`, including when the app wasn't blocked. It doesn't
restore the old child, so issue a new child for the app. It returns `401` if the
parent has been revoked or expired.

## List grants

`GET /auth/grant/sessions` requires a root session and includes active parents
and children, so Ring can group apps under their parent. `kind` is `direct`,
`parent` or `child`. Children also have `parent_id`. A child doesn't appear
once its parent is inactive.

A parent appears only after the homeserver first sees it, normally through its
first child exchange.

The SDK exposes these fields through `GrantManager.list()`: `kind` and `parent_id`
in Rust, and `kind` and `parentId` in JavaScript.

## Upgrade a homeserver

The `m20261103_add_grant_delegation` migration runs automatically at startup. It
marks existing grants as `direct` and doesn't rewrite them, so existing grants and
sessions keep working.

Upgrade every homeserver node before relying on `grant-delegation`. A node that
hasn't been upgraded rejects the new token types and won't enforce blocks. Older
SDKs ignore the new listing fields, and newer SDKs treat a missing `kind` as
`direct`.

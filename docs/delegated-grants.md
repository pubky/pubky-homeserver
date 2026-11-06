# Parent and child grants

A parent grant lets one trusted holder, such as Pubky Accounts, sign in
first-party apps without asking the user to approve each one in Ring. The same
approval can give the holder encryption keys, which it narrows for each app. This
guide is for developers who build Accounts, Ring and SDK integrations. It covers
the sign-in flow, key delivery, the token format, the homeserver API and the grant
lifecycle.

Existing direct grants don't change. Check that `GET /info` lists
`grant-delegation` before you use this API, or use the SDK's
[support check](#check-homeserver-support). Older homeservers reject the new token
types.

## Sign in apps

One Ring approval works for every first-party app while the parent is valid:

1. Accounts asks Ring for a parent grant, and the user approves it once.
2. An app redirects the user to Accounts.
3. Accounts checks the app against its catalog, issues a child grant and redirects
   back with an encrypted approval.
4. The app verifies the approval and exchanges the child grant for its own session.

The SDK supports Ring and Accounts, which handle steps 1 and 3. Apps build the
request and read the response using the [approval formats](#approval-formats).

> [!WARNING]
> Approving `e` makes Accounts a holder of the user's keys. It can decrypt existing
> and future data under the approved scopes, and it can give narrower keys to apps.
> Signing out or revoking a grant doesn't take back delivered keys, and there's no
> key rotation. Serve Accounts from its own origin, without third-party scripts,
> and read the [scoped encryption keys guide](scoped-encryption-keys.md).

The examples below use the JS SDK. For Rust, see
[Issue child grants through a parent grant](../pubky-sdk/README.md#issue-child-grants-through-a-parent-grant).

### Check homeserver support

Ring should check the user's homeserver before it shows a parent-grant approval:

```js
const support = await pubky.grantDelegationSupport(userPublicKey);
```

The result is `supported`, `unsupported` or `unknown`. For `unsupported`, tell the
user that their homeserver needs an upgrade. For `unknown`, the check couldn't
finish, for example because the homeserver was unreachable, so offer a retry.
The check covers only the homeserver: Ring must also support `parent_grant` links.

### Get a parent grant in Accounts

Request the parent with `parentGrant: true`, and use your exact HTTPS callback as
the client ID. The SDK keeps the signing key non-extractable, and the request fails
if the browser can't do that.

```js
const flow = await pubky.startGrantAuthFlow(
  "/pub/:rwe,/priv/:rwe",
  AuthFlowKind.signin(),
  { clientId: "https://accounts.example/auth/callback", parentGrant: true },
);
renderQr(flow.authorizationUrl);

const parent = await flow.awaitParentGrant();
const { id } = await pubky.parentGrantStore.save(parent);
```

`save()` stores the approval and its keys as plaintext in IndexedDB. Any script on
the Accounts origin can read them. To finish a flow after a reload, use
`flow.saveDelegated()` and `pubky.resumeDelegatedGrantAuthFlow()`.

### Approve the parent in Ring

The request is a `pubkyauth://parent_grant` link. `approve_auth_with_capabilities`
approves it like any other request and can remove actions. Ask for encryption
consent separately from storage consent, and explain that Accounts can decrypt
existing and future data under those scopes and share narrower keys with suite
apps. If the user declines, approve the capabilities without `e`, such as
`/pub/:rw,/priv/:rw`. Accounts then holds no keys.

### Issue a child grant in Accounts

Parse the app's request and check it against your catalog first. The SDK only
checks the request against the parent's limits. Accounts decides which apps exist
and what each one may ask for.

Redirect only to a callback that's in your catalog. `declinedUrl()` points at the
callback the request named, so redirecting for an unknown app would make Accounts
an open redirect. Show an error page instead.

```js
const request = ChildGrantRequest.parse(location.href);
const app = catalog.get(request.clientId);
if (!app) {
  showUnknownAppError();
  return;
}
if (!app.allows(request.capabilities)) {
  location.replace(request.declinedUrl("access_denied"));
  return;
}

const parent = await pubky.parentGrantStore.restore(id);
try {
  location.replace(await parent.issueChild(request));
} catch (error) {
  if (error.data?.denial !== "insufficient_permissions") throw error;
  location.replace(request.declinedUrl(error.data.denial));
}
```

Restore the parent for each request instead of keeping it in memory, so a sign-out
in another tab takes effect. Don't log the callback URL. Its fragment carries the
encrypted approval.

A request that exceeds the parent, such as keys the user declined to share, gets
`insufficient_permissions`. Tell the user what's missing rather than starting
another Ring approval automatically.

### Reconnect an app

When the user removes an app, for example in Ring, the homeserver blocks new
children for that app under this parent. After the user confirms in Accounts that
they want the app back, clear the block, then issue a new child:

```js
await pubky.parentGrantStore.reconnectApp(id, "https://chat.example/auth/callback");
```

Reconnecting doesn't need Ring. Clearing a block that doesn't exist succeeds, so
you can retry the call.

### Sign out of Accounts

`pubky.parentGrantStore.signOut(id)` stops issuance and deletes the saved keys,
then revokes the parent, all its children and their sessions. If the request fails,
only what's needed to retry remains. Call `signOut` or `restore` to retry.

`browserSessionStore.clearAll()` doesn't delete saved parents or their signing
keys. Sign them out with `parentGrantStore.signOut`.

## Approval formats

Each approval is a signed JWS encrypted with HPKE to the recipient's temporary
public key (`epk`). Only the public grants ever reach the homeserver. It never
receives keys or approvals.

| Approval | JWS `typ` | Signed by | Payload fields |
| --- | --- | --- | --- |
| Parent | `pubky-parent-approval` | The user's identity key | `parent`, `recipient`, `encryption_keys` |
| Child | `pubky-child-approval` | The key in the parent's `cnf` | `parent`, `child`, `recipient`, `state`, `encryption_keys` |

`parent` and `child` are the grant JWS values, and `recipient` is `epk` in unpadded
base64url. `encryption_keys` has the [scoped key bundle](scoped-encryption-keys.md#approval-delivery)
format, with keys for exactly the grant's `e` scopes. A child's bundle holds keys
derived from the parent's, so it never exposes a wider seed or the parent's approval.

These approvals have no version number. A new format gets a new type name, and
older software rejects names it doesn't know, so it can't misread a new approval.

The requests and responses look like this:

| Step | URL |
| --- | --- |
| Accounts to Ring | `pubkyauth://parent_grant?caps=…&relay=…&cid=…&cpk=…&epk=…` |
| App to Accounts | `<accounts URL>?cid=…&caps=…&cpk=…&epk=…&state=…` |
| Accounts to app, approved | `<callback>#approval=<base64url HPKE message>&state=…` |
| Accounts to app, declined | `<callback>#error=<code>&state=…` |

The error code is `access_denied`, `cancelled` or `insufficient_permissions`.

The receiver rejects an approval unless all of these are true:

- Every signature and JWS type is correct, and the chain meets the
  [homeserver's rules](#tokens).
- The recipient, client key and client ID match the pending request. For a child,
  so does the signed `state`.
- The approved capabilities stay within the request.
- The bundle has keys for exactly the grant's `e` scopes, with none missing or extra.

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

## Roll out key delivery

Key delivery adds no homeserver endpoint or migration. Roll out support in this
order:

1. Upgrade homeservers.
2. Release the SDK and native bindings, then Ring. Older signers reject
   `parent_grant` links with an error instead of signing anything.
3. Enable key delivery in Accounts, and release apps that request `e`.

A parent approval for `/pub/:rwe,/priv/:rwe` fits the relay's default 2 KiB body
limit. If you add more or longer scopes, check the
[relay limits](scoped-encryption-keys.md#relay-limits).

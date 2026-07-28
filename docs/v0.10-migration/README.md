# Migrating to v0.10

This guide covers applications upgrading from `v0.9.x`. `v0.10` includes multiple breaking changes and most importantly, a new and more secure grant authentication system.

It is strongly recommended to upgrade to **Grant authentication. Cookie authentication is now deprecated** and will be removed in future versions. It is [insecure](https://github.com/pubky/pubky-core/issues/520). Cookie auth still exists in v0.10, but the SDK now names the cookie-compatible APIs explicitly. If you do not want to upgrade to grant-auth then the main migration is to replace the old generic sign-in/up methods with the new `*Cookie` methods.


## Migrate Authentication System

Migrate to new and secure [Grant authentication system](./grant-auth.md) or keep the [Cookie authentication system](./cookie-auth.md).




## Deep Link Parsing

If your Rust app parses signin or signup deep links directly, the parameter accessors changed.

Use `params()` instead of the old direct methods.

```rust
let params = deep_link.params();

let caps = &params.capabilities;
let relay = &params.relay;
let secret = &params.secret;
```

For signup deep links:

```rust
let params = signup_deep_link.params();

let homeserver = &params.homeserver;
let signup_token = params.signup_token.as_deref();
```

If your code matches on `DeepLink`, make sure it has a fallback or handles all variants. v0.10 adds extra variants, so exhaustive matches written against `v0.9.x` may fail to compile.


## Capability Path Matching

v0.10 tightens capability validation in various ways, for example a trailing slash is now significant.

Directory scopes should end with `/`.

```text
/pub/app/:rw covers /pub/app/file.txt
/pub/app:rw only covers /pub/app
```

If your app intends to grant access to everything under an app directory, use a trailing slash.

```rust
let caps = Capabilities::builder()
    .read_write("/pub/my-cool-app/")
    .unwrap()
    .finish();
```

```js
const caps = "/pub/my-cool-app/:rw";
```

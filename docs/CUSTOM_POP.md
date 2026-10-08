# Sign and verify custom data

A custom proof of possession (PoP) lets a grant session sign arbitrary JSON with
its client key. The result contains both the original root-signed `grant` JWS and
the client-signed `pop` JWS, so a recipient can verify the identity chain offline.
Creation works with local and browser-held keys and needs no fresh bearer token.

## Rust

```rust
let credentials = session.as_grant()?.create_custom_pop(serde_json::json!({
    "audience": "my-service",
    "challenge": challenge,
})).await?;

// On the recipient, after transporting the entire credentials bundle:
let verified = pubky::verify_custom_grant_pop(
    &credentials, pubky::DEFAULT_CUSTOM_POP_CLOCK_SKEW,
)?;
let identity = verified.identity();
let grant = verified.grant_claims();
let data = verified.data();

// Or choose an explicit allowance (Duration::ZERO disables it):
let verified = pubky::verify_custom_grant_pop(
    &credentials, std::time::Duration::from_secs(60),
)?;
```

## JavaScript

```js
import { verifyCustomGrantPop } from "@synonymdev/pubky";

const credentials = await session.grant.createCustomPop({
  audience: "my-service",
  challenge,
});

// On the recipient; works in Node.js and browsers:
const { identity, grantClaims, data } = verifyCustomGrantPop(credentials);

// Optional override, in whole seconds (zero disables the allowance):
const verified = verifyCustomGrantPop(credentials, { clockSkewSeconds: 60 });
```

`data` can be any JSON value: an object, array, string, number, boolean, or `null`.
Encode binary data as a string. The proof payload is `{ "gid": "<grant ID>", "data": ... }`
and its JWS type is `pubky-custom-pop-v1`, distinct from homeserver proofs.
Application fields remain nested under `data` and cannot overwrite `gid`.

## Verification contract

The verifier checks the root signature on the grant, the proof signature against
the grant's `cnf` key, and the proof's grant ID. It also requires
`iat <= now + allowance`, `now < exp`, and `iat < exp` for the grant.
Rust requires an explicit allowance; `DEFAULT_CUSTOM_POP_CLOCK_SKEW` provides
30 seconds. JavaScript defaults to 30 seconds. Zero disables the allowance.
Expiry remains strict, regardless of the allowance. Rust truncates `Duration`
to whole seconds; JavaScript accepts integer seconds from 0 to 4294967295.
The verifier returns the verified identity, grant claims, and data.

Proof creation checks expiry and the grant's validity ordering, but leaves future
issue times to the recipient's clock-skew policy. The allowance applies only to
the grant's `iat`; your application validates any timestamps inside custom data.

Your application defines and checks the data's meaning, including audience,
challenge, freshness, and authorization. For a single-use authentication exchange,
issue a challenge and atomically consume it after verification. Repeated calls to
the verifier succeed while the grant is valid; the SDK stores no replay state.
Apply input size limits at your transport boundary.

Verification does not contact the homeserver or check revocation. Grant storage
capabilities do not establish service-specific permissions. If you create a
service session, bound its lifetime by the verified grant's `exp`.

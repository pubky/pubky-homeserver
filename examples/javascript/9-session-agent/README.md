# Session agent: one sign-in across first-party origins

Static pages that show `connectSessionAgent` / `serveSessionAgent`: a page on a dedicated origin (the *agent*) owns one grant session, and apps on other same-site origins use it through a hidden iframe without any prompt of their own.

Ports stand in for hostnames. The browser treats `localhost:8081`, `localhost:8082` and `localhost:8083` as three origins of one site, like `pubky.app`, `shop.pubky.app` and `auth.pubky.app`. `127.0.0.1` is another site, like `example.com`.

| Role | Origin |
|---|---|
| Agent (`auth.pubky.app`) | `http://localhost:8083/agent.html` |
| App (`pubky.app`) | `http://localhost:8081/app.html` |
| App (`shop.pubky.app`) | `http://localhost:8082/app.html` |
| Cross-site app, allowlisted | `http://127.0.0.1:8084/app.html` |
| Same-site app, not allowlisted | `http://localhost:8085/app.html` |

## Run by hand

Build the SDK package and start a testnet (see the [examples README](../README.md)), then:

```bash
node serve.mjs
```

1. Open the agent page and click **Sign in**. The page creates a throwaway testnet account and approves its own grant request, standing in for Ring. The session is saved with `browserSessionStore` and served to the allowlisted origins.
2. Open the two app pages. Both are signed in as that user with no interaction, write notes and read each other's.
3. Open the uninvited and cross-site pages. The first is refused by the allowlist; the second connects but sees no session, because the browser gives a cross-site frame its own empty storage.
4. Sign out from any app. The agent revokes the grant; every app loses the session.

## Automated check

The same flow runs in headless Electron as part of the SDK package tests: `npm run test-browser:agent` in `pubky-sdk/bindings/js/pkg`. It also asserts that app pages never exchange a grant themselves, that each app recovers from a bearer rotation with exactly one retried request, and that the user holds one grant for all of them.

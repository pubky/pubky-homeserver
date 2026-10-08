# SSO with a session agent

Static pages that show `listenSessionAgent` and `connectSessionAgent`: a page on a dedicated origin (the *agent*) owns one grant session, and apps on other same-site origins borrow it through an iframe. The user signs in once, inside that frame, and every app on the site follows. See [docs/sso-agent.md](../../../docs/sso-agent.md) for the protocol and deployment requirements.

Ports stand in for hostnames. The browser treats `localhost:8081`, `localhost:8082` and `localhost:8083` as three origins of one site, like `pubky.app`, `shop.pubky.app` and `auth.pubky.app`. `127.0.0.1` is another site, like `example.com`.

| Role | Origin |
|---|---|
| Agent (`auth.pubky.app`) | `http://localhost:8083/` |
| App (`pubky.app`) | `http://localhost:8081/` |
| App (`shop.pubky.app`) | `http://localhost:8082/` |
| Cross-site app, allowlisted | `http://127.0.0.1:8084/` |

The agent is served with the headers from the docs, including `frame-ancestors`. The pages have no build step; the agent shows the `pubkyauth://` link and a stand-in approval button instead of rendering a QR code (see [example 2](../2-auth-flow) for a QR widget).

## Run by hand

Build the SDK package and start a testnet (see the [examples README](../README.md)), then:

```bash
node serve.mjs
```

1. Open the first app. It is not signed in, so it shows the agent frame. Click **Approve with a throwaway testnet account**, which stands in for scanning the QR code with Ring. The app flips to signed in and hides the frame.
2. Open the second app. It is signed in with no interaction. Write notes from both and read each other's.
3. Open the cross-site page. It is allowlisted but sees `signed-out`, because the browser gives a cross-site frame its own empty storage.
4. Sign out from any app. The agent revokes the grant and every app shows the frame again.

## Automated check

The same flow runs in headless Electron as part of the SDK package tests: `npm run test-browser:sso` in `pubky-sdk/bindings/js/pkg`. It also covers a bearer rotation with one retry per app, an origin that is not allowlisted, an app that asks for more than the shared scope, and that the user holds one grant for all apps.

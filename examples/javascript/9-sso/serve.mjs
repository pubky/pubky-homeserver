// Static server that plays four origins on one machine.
//
// Ports stand in for hostnames: the browser treats every `localhost:<port>`
// as a distinct origin but one site, exactly like `pubky.app` and
// `shop.pubky.app`. `127.0.0.1` is a different site, like `example.com`.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { dirname, extname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const sdk = join(here, "../../../pubky-sdk/bindings/js/pkg");

export const ORIGINS = {
  agent: "http://localhost:8083", // "auth.pubky.app"
  app: "http://localhost:8081", // "pubky.app"
  shop: "http://localhost:8082", // "shop.pubky.app"
  crossSite: "http://127.0.0.1:8084", // allowlisted but a different site
};
const ALLOWED = [ORIGINS.app, ORIGINS.shop, ORIGINS.crossSite];

const types = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".mjs": "text/javascript; charset=utf-8",
};

/** The agent page ships with the headers from docs/sso-agent.md. */
function agentHeaders(res) {
  res.setHeader("Content-Security-Policy", [
    "default-src 'self'",
    "script-src 'self' 'wasm-unsafe-eval'",
    "connect-src http://localhost:* http://127.0.0.1:*", // the testnet; `https:` in production
    `frame-ancestors ${ALLOWED.join(" ")}`,
    "base-uri 'none'",
    "form-action 'none'",
  ].join("; "));
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "no-referrer");
}

function handler(role) {
  return (req, res) => {
    const path = new URL(req.url, "http://x").pathname;
    const file = path.startsWith("/pubky/")
      ? join(sdk, path.slice("/pubky/".length))
      : join(here, role, path === "/" ? "/index.html" : path);
    readFile(file).then(
      (body) => {
        if (role === "agent") agentHeaders(res);
        res.writeHead(200, { "Content-Type": types[extname(file)] ?? "application/octet-stream" });
        res.end(body);
      },
      () => res.writeHead(404).end("not found"),
    );
  };
}

/** One server per origin; ports alone tell them apart, so bind every interface. */
export async function listen() {
  const servers = await Promise.all(
    Object.entries(ORIGINS).map(([name, origin]) => new Promise((resolve, reject) => {
      const server = createServer(handler(name === "agent" ? "agent" : "app"));
      server.once("error", reject);
      server.listen(Number(new URL(origin).port), () => resolve(server));
    })),
  );
  return { close: () => servers.forEach((server) => server.close()) };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await listen();
  for (const [role, origin] of Object.entries(ORIGINS)) console.log(`${role.padEnd(10)} ${origin}`);
  console.log(`\nApps: ${ORIGINS.app}  ${ORIGINS.shop}  ${ORIGINS.crossSite}\nAgent (standalone): ${ORIGINS.agent}`);
}

// Minimal CLI helpers to keep examples focused on Pubky SDK.
import mri from "mri";
import prompt from "password-prompt";
import { readFile as fsReadFile } from "node:fs/promises";

/**
 * Parse CLI args with tiny defaults. Keeps examples clean.
 * @param {string[]} argv - usually process.argv.slice(2)
 * @param {object} [opts]
 * @param {object} [opts.aliases] - mri alias map (e.g. { h: 'help' })
 * @param {object} [opts.defaults] - default values
 * @param {string} [opts.usage] - printed when --help is passed
 * @returns {object} parsed options
 */
export function args(argv, { aliases = {}, defaults = {}, usage } = {}) {
  const a = mri(argv, {
    alias: aliases,
    default: defaults,
    boolean: ["testnet", "help"],
  });
  if (a.help && usage) {
    console.log(usage);
    process.exit(0);
  }
  return a;
}

/**
 * Check whether an SDK request failed because the resource already exists.
 * @param {unknown} error
 * @returns {boolean}
 */
export function isConflictError(error) {
  return (
    error?.name === "RequestError" &&
    typeof error.data === "object" &&
    error.data !== null &&
    error.data.statusCode === 409
  );
}

/**
 * Prompt for a hidden passphrase (Node 20+).
 * @param {string} message
 * @returns {Promise<string>}
 */
export function promptHidden(message) {
  return prompt(message, { method: "hide" }).then((value) =>
    value.replace(/[\r\n]+$/u, ""),
  );
}

/**
 * Read a file as Uint8Array (for recovery files).
 * @param {string} path
 * @returns {Promise<Uint8Array>}
 */
export async function readFileUint8(path) {
  const buf = await fsReadFile(path);
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}

/**
 * Pretty-print a fetch Response (method used by `request.mjs`).
 * @param {Response} res
 * @param {Uint8Array|string} body
 */
export function printHttpResponse(res, body) {
  console.log(`< Response:`);
  console.log(
    `< ${res.httpVersion || "HTTP/?"} ${res.status} ${res.statusText || ""}`,
  );
  for (const [k, v] of res.headers) console.log(`< ${k}: ${v}`);
  if (body instanceof Uint8Array) {
    try {
      console.log("<\n" + Buffer.from(body).toString("utf8"));
    } catch {
      console.log("<\n" + body);
    }
  } else {
    console.log("<\n" + body);
  }
}

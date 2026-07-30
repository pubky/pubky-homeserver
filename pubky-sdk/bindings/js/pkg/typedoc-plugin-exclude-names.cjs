// @ts-check
const { Converter } = require("typedoc");

/** Names to hide from the generated documentation. */
const HIDDEN = new Set([
  "IntoUnderlyingByteSource",
  "IntoUnderlyingSink",
  "IntoUnderlyingSource",
  "Level", // wasm-bindgen log level enum
  "ReadableStreamType",
  "CapabilitiesTail",
]);

/** @param {import("typedoc").Application} app */
exports.load = function load(app) {
  app.converter.on(Converter.EVENT_RESOLVE_BEGIN, (context) => {
    for (const reflection of Object.values(context.project.reflections)) {
      if (HIDDEN.has(reflection.name)) {
        context.project.removeReflection(reflection);
      }
    }
  });
};

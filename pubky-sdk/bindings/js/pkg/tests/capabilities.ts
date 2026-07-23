import test from "tape";
import { validateCapabilities } from "../index.js";
import { assertPubkyError } from "./utils.js";

test("validateCapabilities normalizes valid capabilities", (t) => {
  t.equal(
    // @ts-ignore: unordered actions are accepted and normalized at runtime.
    validateCapabilities("/pub/a/:wr,/priv/b/:r"),
    "/pub/a/:rw,/priv/b/:r",
    "normalize wr->rw and preserve valid entries",
  );
  t.equal(validateCapabilities(""), "", "accepts an empty capability list");

  t.end();
});

test("validateCapabilities reports the first invalid capability", (t) => {
  try {
    // @ts-ignore: malformed capability string for runtime validation.
    validateCapabilities("/pub/a/:rw,/x:y,/pub/b/:x");
    t.fail("validateCapabilities should throw on malformed entries");
  } catch (error) {
    assertPubkyError(t, error);
    t.equal(error.name, "InvalidInput", "throws InvalidInput on bad entries");
    t.ok(
      error.message.includes("/x:y"),
      "message identifies the first offending entry",
    );
    t.ok(
      error.data &&
        typeof error.data === "object" &&
        Array.isArray((error.data as { invalidEntries?: unknown }).invalidEntries),
      "error.data exposes invalidEntries array",
    );
    if (
      error.data &&
      typeof error.data === "object" &&
      Array.isArray((error.data as { invalidEntries?: unknown }).invalidEntries)
    ) {
      t.deepEqual(
        (error.data as { invalidEntries: string[] }).invalidEntries,
        ["/x:y"],
        "invalidEntries contains the first malformed token",
      );
    }
  }

  t.end();
});

test("validateCapabilities rejects malformed list entries", (t) => {
  const cases = [
    { input: "/pub/a/:", invalidEntry: "/pub/a/:" },
    { input: ",/pub/a/:r", invalidEntry: "" },
    { input: "/pub/a/:r,", invalidEntry: "" },
    { input: "/pub/a/:r,,/priv/b/:w", invalidEntry: "" },
  ];

  for (const { input, invalidEntry } of cases) {
    try {
      validateCapabilities(input as any);
      t.fail(`accepted malformed capabilities: ${input}`);
    } catch (error) {
      assertPubkyError(t, error);
      t.deepEqual(
        (error.data as { invalidEntries: string[] }).invalidEntries,
        [invalidEntry],
        `rejects malformed capabilities: ${input}`,
      );
    }
  }

  t.end();
});

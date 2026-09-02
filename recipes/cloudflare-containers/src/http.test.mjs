import assert from "node:assert/strict";
import test from "node:test";

import { errorMessage, isAuthorized, json } from "./http.mjs";

test("management authorization requires the exact bearer token", () => {
  assert.equal(
    isAuthorized(
      new Request("https://example.test/session", {
        headers: { authorization: "Bearer correct" },
      }),
      "correct",
    ),
    true,
  );
  assert.equal(
    isAuthorized(
      new Request("https://example.test/session", {
        headers: { authorization: "Bearer wrong" },
      }),
      "correct",
    ),
    false,
  );
  assert.equal(isAuthorized(new Request("https://example.test/session"), ""), false);
});

test("JSON responses disable caching", async () => {
  const response = json({ running: true }, 201);
  assert.equal(response.status, 201);
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.deepEqual(await response.json(), { running: true });
});

test("unknown errors receive a safe string representation", () => {
  assert.equal(errorMessage(new Error("failed")), "failed");
  assert.equal(errorMessage("failed"), "failed");
});

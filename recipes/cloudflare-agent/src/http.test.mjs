import assert from "node:assert/strict";
import test from "node:test";

import {
  computerInvocation,
  deriveHostLabel,
  isAuthorized,
  lastPathSegment,
  truncateOutput,
  validateCommand,
} from "./http.mjs";

test("authorization requires the exact configured bearer token", () => {
  const request = new Request("https://example.test/agents/herdr-agent/demo", {
    headers: { authorization: "Bearer token" },
  });
  assert.equal(isAuthorized(request, "token"), true);
  assert.equal(isAuthorized(request, "other"), false);
  assert.equal(isAuthorized(request, undefined), false);
});

test("agent routes use their final path segment", () => {
  assert.equal(lastPathSegment("/agents/herdr-agent/demo/publisher"), "publisher");
  assert.equal(lastPathSegment("/"), "");
});

test("host labels are valid, deterministic, and bounded", () => {
  const label = deriveHostLabel("Cloudflare Agent", "Customer / Workspace ".repeat(8));
  assert.match(label, /^[a-z0-9][a-z0-9._-]*$/);
  assert.ok(label.length <= 64);
  assert.equal(deriveHostLabel("prefix", "name"), "prefix-name");
});

test("computer commands reject empty, non-string, NUL, and oversized input", () => {
  assert.equal(validateCommand("  pwd  "), "pwd");
  assert.throws(() => validateCommand(""), /must not be empty/);
  assert.throws(() => validateCommand(42), /must be a string/);
  assert.throws(() => validateCommand("echo\0bad"), /NUL/);
  assert.throws(() => validateCommand("x".repeat(4097)), /4096/);
});

test("computer commands are passed out-of-band to a fixed output-capping wrapper", () => {
  const untrusted = "printf '%s' \"$HOME; still data\"";
  const invocation = computerInvocation(`  ${untrusted}  `);
  assert.equal(invocation.env.ATTACHED_COMPUTER_COMMAND, untrusted);
  assert.equal(invocation.command.includes(untrusted), false);
  assert.match(invocation.command, /setpriv --no-new-privs --reuid=10001/);
  assert.equal((invocation.command.match(/head -c 32768/g) ?? []).length, 2);
});

test("computer output is bounded", () => {
  assert.equal(truncateOutput("small"), "small");
  const truncated = truncateOutput("x".repeat(33 * 1024));
  assert.match(truncated, /\[truncated\]$/);
  assert.ok(truncated.length < 33 * 1024);
});

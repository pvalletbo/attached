"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const SessionModel = require("../SessionModel.js");

test("configuration defaults to typed passwords and validates explicit providers", () => {
  assert.equal(SessionModel.encryptionPasswordProvider(""), "password");
  assert.equal(
    SessionModel.encryptionPasswordProvider('{"encryptionPasswordProvider":"password"}'),
    "password"
  );
  assert.equal(
    SessionModel.encryptionPasswordProvider('{"encryptionPasswordProvider":"1password"}'),
    "1password"
  );
  assert.throws(() => SessionModel.encryptionPasswordProvider("[]"), /JSON object/);
  assert.throws(
    () => SessionModel.encryptionPasswordProvider('{"encryptionPasswordProvider":"keyring"}'),
    /password.*1password/
  );
});

test("catalog and terminal commands honor the provider and preserve targets as argv", () => {
  assert.deepEqual(SessionModel.catalogCommand("password"), [
    "attached",
    "sessions",
    "--json",
    "--password-stdin"
  ]);
  assert.deepEqual(SessionModel.catalogCommand("1password"), [
    "attached",
    "--use-1password",
    "sessions",
    "--json"
  ]);

  const session = { target: "travel/shell; touch /tmp/nope" };
  assert.deepEqual(SessionModel.terminalCommand(session, "password"), [
    "omarchy-launch-terminal",
    "attached",
    "attach",
    "travel/shell; touch /tmp/nope"
  ]);
  assert.deepEqual(SessionModel.terminalCommand(session, "1password"), [
    "omarchy-launch-terminal",
    "attached",
    "--use-1password",
    "attach",
    "travel/shell; touch /tmp/nope"
  ]);
  assert.throws(() => SessionModel.terminalCommand(null, "password"), /session target/);
  assert.throws(() => SessionModel.catalogCommand("unknown"), /unsupported/);
});

test("catalog errors give provider-specific guidance without echoing stderr", () => {
  assert.match(
    SessionModel.catalogErrorMessage(
      "Error: 1Password is unavailable; unlock or sign in with the op CLI and retry",
      1,
      "1password"
    ),
    /Open or unlock 1Password.*Ctrl\+O.*Ctrl\+R/
  );
  assert.match(
    SessionModel.catalogErrorMessage(
      "Error: encrypted local secret authentication failed",
      1,
      "1password"
    ),
    /could not be unlocked with 1Password.*attached --use-1password sessions --json/
  );

  const onePasswordGeneric = SessionModel.catalogErrorMessage(
    "private backend detail",
    7,
    "1password"
  );
  assert.match(onePasswordGeneric, /exit 7.*attached --use-1password sessions --json/);
  assert.doesNotMatch(onePasswordGeneric, /private backend detail/);

  const passwordFailure = SessionModel.catalogErrorMessage(
    "encrypted local secret authentication failed: private ciphertext detail",
    1,
    "password"
  );
  assert.match(passwordFailure, /could not unlock Attached.*Ctrl\+R/);
  assert.doesNotMatch(passwordFailure, /ciphertext/);

  const passwordGeneric = SessionModel.catalogErrorMessage("private backend detail", 9, "password");
  assert.match(passwordGeneric, /exit 9.*re-enter.*attached sessions --json/);
  assert.doesNotMatch(passwordGeneric, /private backend detail/);
});

test("filterSessions performs stable case-insensitive fuzzy ranking", () => {
  const sessions = [
    { target: "home/slow", host: "home", session: "slow", publishedAt: null },
    { target: "office/work", host: "office", session: "work", publishedAt: null },
    { target: "travel/shell", host: "travel", session: "shell", publishedAt: null },
    { target: "office/web", host: "office", session: "web", publishedAt: null }
  ];

  assert.deepEqual(
    SessionModel.filterSessions(sessions, "OFFWK").map((row) => row.target),
    ["office/work"]
  );
  assert.deepEqual(
    SessionModel.filterSessions(sessions, "ts").map((row) => row.target),
    ["travel/shell"]
  );
  assert.deepEqual(
    SessionModel.filterSessions(sessions, "").map((row) => row.target),
    sessions.map((row) => row.target)
  );
  assert.deepEqual(
    SessionModel.filterSessions(sessions, "office/w").map((row) => row.target),
    ["office/work", "office/web"]
  );
});

test("parseCatalog accepts the public Attached schema and rejects unsafe rows", () => {
  const rows = SessionModel.parseCatalog(JSON.stringify([
    {
      target: "office/deep work",
      host: "office",
      session: "deep work",
      publishedAt: "2026-08-29T12:34:56Z"
    },
    {
      target: "travel/shell; touch /tmp/nope",
      host: "travel",
      session: "shell; touch /tmp/nope",
      publishedAt: null
    }
  ]));

  assert.deepEqual(rows.map((row) => row.target), [
    "office/deep work",
    "travel/shell; touch /tmp/nope"
  ]);
  assert.throws(() => SessionModel.parseCatalog("not json"), /valid JSON/);
  assert.throws(
    () => SessionModel.parseCatalog('{"target":"office/work"}'),
    /JSON array/
  );
  assert.throws(
    () => SessionModel.parseCatalog('[{"target":"office/work","host":"office"}]'),
    /row 1.*session/
  );
  assert.throws(
    () => SessionModel.parseCatalog('[{"target":"no-slash","host":"office","session":"work"}]'),
    /row 1.*target/
  );
  assert.throws(
    () => SessionModel.parseCatalog(JSON.stringify(Array.from({ length: 4097 }, (_, index) => ({
      target: "host/session" + index,
      host: "host",
      session: "session" + index
    })))),
    /too many sessions/
  );
});

"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const SessionModel = require("../SessionModel.js");

test("terminalCommand uses 1Password and preserves the target as one argv element", () => {
  assert.deepEqual(
    SessionModel.terminalCommand({ target: "travel/shell; touch /tmp/nope" }),
    [
      "omarchy-launch-terminal",
      "attached",
      "--use-1password",
      "attach",
      "travel/shell; touch /tmp/nope"
    ]
  );
  assert.throws(() => SessionModel.terminalCommand(null), /session target/);
});

test("catalog errors give actionable 1Password guidance without echoing stderr", () => {
  assert.match(
    SessionModel.catalogErrorMessage(
      "Error: 1Password is unavailable; unlock or sign in with the op CLI and retry",
      1
    ),
    /Open or unlock 1Password.*Ctrl\+O.*Ctrl\+R/
  );
  assert.match(
    SessionModel.catalogErrorMessage(
      "Error: encrypted local secret authentication failed",
      1
    ),
    /could not be unlocked with 1Password.*attached --use-1password sessions --json/
  );

  const generic = SessionModel.catalogErrorMessage("private backend detail", 7);
  assert.match(generic, /exit 7.*attached --use-1password sessions --json/);
  assert.doesNotMatch(generic, /private backend detail/);
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

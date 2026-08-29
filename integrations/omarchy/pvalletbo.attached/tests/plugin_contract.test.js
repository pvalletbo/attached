"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const plugin = path.resolve(__dirname, "..");

test("manifest declares a loadable third-party overlay", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(plugin, "manifest.json"), "utf8"));
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.id, "pvalletbo.attached");
  assert.deepEqual(manifest.kinds, ["overlay"]);
  assert.equal(manifest.entryPoints.overlay, "Overlay.qml");
  assert.ok(fs.statSync(path.join(plugin, manifest.entryPoints.overlay)).isFile());
});

test("overlay supports safe catalog loading, keyboard and pointer activation", () => {
  const qml = fs.readFileSync(path.join(plugin, "Overlay.qml"), "utf8");
  for (const contract of [
    'command: ["attached", "sessions", "--json"]',
    "SessionModel.parseCatalog",
    "SessionModel.filterSessions",
    "SessionModel.terminalCommand",
    "Quickshell.execDetached",
    "Qt.Key_Up",
    "Qt.Key_Down",
    "Qt.Key_Return",
    "onClicked:",
    "anchors.right: parent.right",
    "forceActiveFocus()",
    "console.info",
    "console.warn",
    "property var shell: null",
    "property var manifest: null",
    "function dismiss()",
    "shell.hide("
  ]) {
    assert.match(qml, new RegExp(contract.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")), contract);
  }
  assert.doesNotMatch(qml, /\b(?:bash|sh)\b.*-c/);
  assert.equal(
    (qml.match(/\bText\s*\{/g) || []).length,
    (qml.match(/textFormat:\s*Text\.PlainText/g) || []).length,
    "every Text element must render untrusted session/query data as plain text"
  );
});

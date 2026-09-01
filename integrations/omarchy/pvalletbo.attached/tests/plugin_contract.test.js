"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const plugin = path.resolve(__dirname, "..");
const integration = path.resolve(plugin, "..");
const repository = path.resolve(integration, "..", "..");

test("manifest declares a loadable third-party overlay", () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(plugin, "manifest.json"), "utf8"));
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.id, "pvalletbo.attached");
  assert.deepEqual(manifest.kinds, ["overlay"]);
  assert.equal(manifest.entryPoints.overlay, "Overlay.qml");
  assert.ok(fs.statSync(path.join(plugin, manifest.entryPoints.overlay)).isFile());
});

test("configuration and documentation match both password providers", () => {
  const config = JSON.parse(fs.readFileSync(path.join(integration, "config.json"), "utf8"));
  assert.deepEqual(config, { encryptionPasswordProvider: "password" });

  const readme = fs.readFileSync(path.join(integration, "README.md"), "utf8");
  for (const contract of [
    "AI contribution notice",
    "encryptionPasswordProvider",
    '"password"',
    '"1password"',
    "attached sessions --json --password-stdin",
    "attached --use-1password sessions --json",
    "Ctrl+O",
    "qmlformat",
    "real Omarchy 4.0.1 Wayland session"
  ]) {
    assert.match(readme, new RegExp(contract.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")), contract);
  }

  const rootReadme = fs.readFileSync(path.join(repository, "README.md"), "utf8");
  assert.match(rootReadme, /AI contribution notice/);
  assert.match(rootReadme, /Omarchy Shell session picker/);
});

test("overlay supports safe catalog loading, keyboard and pointer activation", () => {
  const qml = fs.readFileSync(path.join(plugin, "Overlay.qml"), "utf8");
  for (const contract of [
    "FileView",
    'path: root.configHome + "/attached/omarchy.json"',
    "SessionModel.catalogCommand",
    "stdinEnabled: true",
    "catalogProcess.write",
    "TextInput.Password",
    "stderr: StdioCollector",
    "SessionModel.parseCatalog",
    "SessionModel.filterSessions",
    "SessionModel.catalogErrorMessage",
    "SessionModel.terminalCommand",
    "Quickshell.execDetached",
    '["omarchy-launch-1password"]',
    "Qt.Key_Up",
    "Qt.Key_Down",
    "Qt.Key_Return",
    "Qt.Key_O",
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

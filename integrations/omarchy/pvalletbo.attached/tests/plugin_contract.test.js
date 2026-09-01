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
    "attached sessions --password-stdin",
    "attached --use-1password sessions",
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
    "SessionModel.metadataSummary",
    "SessionModel.terminalCommand",
    "Quickshell.execDetached",
    '["omarchy-launch-1password"]',
    "Qt.Key_Up",
    "Qt.Key_Down",
    "Qt.Key_P",
    "Qt.Key_N",
    "Qt.ControlModifier",
    "Qt.Key_Return",
    "Qt.Key_O",
    "onClicked:",
    "anchors.centerIn: parent",
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
  assert.ok(
    qml.indexOf("text: row.modelData.host") < qml.indexOf("text: row.modelData.session"),
    "host must be the primary row label"
  );
  assert.match(
    qml,
    /text: row\.modelData\.host[\s\S]{0,300}font\.pixelSize: Style\.font\.heading/,
    "host must use the largest row font"
  );
  assert.match(
    qml,
    /Qt\.Key_P[\s\S]{0,120}Qt\.ControlModifier[\s\S]{0,120}root\.moveSelection\(-1\)/,
    "Ctrl+P must move to the previous filtered session"
  );
  assert.match(
    qml,
    /Qt\.Key_N[\s\S]{0,120}Qt\.ControlModifier[\s\S]{0,120}root\.moveSelection\(1\)/,
    "Ctrl+N must move to the next filtered session"
  );
  assert.match(
    qml,
    /text: SessionModel\.metadataSummary\(row\.modelData\)[\s\S]{0,300}font\.pixelSize: Style\.font\.caption/,
    "session metadata must use the smallest row font"
  );
  assert.equal(
    (qml.match(/\bText\s*\{/g) || []).length,
    (qml.match(/textFormat:\s*Text\.PlainText/g) || []).length,
    "every Text element must render untrusted session/query data as plain text"
  );
});

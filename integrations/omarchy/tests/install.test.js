"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const integration = path.resolve(__dirname, "..");

function runInstaller(env) {
  return spawnSync("bash", [path.join(integration, "install.sh")], {
    env,
    encoding: "utf8"
  });
}

test("installer is idempotent and refuses every destructive or partial write", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "attached-omarchy-install-"));
  const home = path.join(root, "home");
  const bin = path.join(root, "bin");
  const config = path.join(home, ".config");
  const log = path.join(root, "commands.log");
  const bindingsPath = path.join(config, "hypr", "bindings.lua");
  const destination = path.join(config, "omarchy", "plugins", "pvalletbo.attached");
  fs.mkdirSync(path.dirname(bindingsPath), { recursive: true });
  fs.mkdirSync(bin, { recursive: true });

  for (const command of ["omarchy", "omarchy-shell"]) {
    fs.writeFileSync(
      path.join(bin, command),
      `#!/bin/sh\nprintf '%s\\n' "${command} $*" >> "$ATTACHED_TEST_LOG"\n`,
      { mode: 0o755 }
    );
  }

  const env = {
    ...process.env,
    HOME: home,
    XDG_CONFIG_HOME: config,
    PATH: `${bin}:${process.env.PATH}`,
    ATTACHED_TEST_LOG: log
  };

  const partialBindings = "-- existing user binding\n-- BEGIN Attached session picker\n";
  fs.writeFileSync(bindingsPath, partialBindings);
  const partial = runInstaller(env);
  assert.notEqual(partial.status, 0);
  assert.match(partial.stderr, /partial or duplicate managed shortcut block/);
  assert.equal(fs.existsSync(destination), false, "preflight failure must not install files");
  assert.equal(fs.readFileSync(bindingsPath, "utf8"), partialBindings);

  fs.writeFileSync(bindingsPath, "-- existing user binding\n");
  for (let run = 0; run < 2; run++) {
    const installed = runInstaller(env);
    assert.equal(installed.status, 0, installed.stderr);
  }

  for (const file of ["manifest.json", "Overlay.qml", "SessionModel.js"])
    assert.ok(fs.statSync(path.join(destination, file)).isFile(), file);

  const bindings = fs.readFileSync(bindingsPath, "utf8");
  assert.equal((bindings.match(/BEGIN Attached session picker/g) || []).length, 1);
  assert.match(bindings, /SUPER \+ CTRL \+ SHIFT \+ H/);
  assert.match(bindings, /omarchy-shell shell toggle pvalletbo\.attached/);

  const checksumPath = path.join(destination, ".attached-plugin-checksums");
  const completeChecksums = fs.readFileSync(checksumPath, "utf8");
  fs.writeFileSync(checksumPath, completeChecksums.split("\n")[0] + "\n");
  const customizedOverlay = path.join(destination, "Overlay.qml");
  fs.appendFileSync(customizedOverlay, "// local customization\n");
  const incompleteProvenance = runInstaller(env);
  assert.notEqual(incompleteProvenance.status, 0);
  assert.match(incompleteProvenance.stderr, /invalid plugin provenance/);
  assert.match(fs.readFileSync(customizedOverlay, "utf8"), /local customization/);

  fs.copyFileSync(path.join(integration, "pvalletbo.attached", "Overlay.qml"), customizedOverlay);
  fs.writeFileSync(checksumPath, completeChecksums);
  fs.appendFileSync(customizedOverlay, "// another local customization\n");
  const modified = runInstaller(env);
  assert.notEqual(modified.status, 0);
  assert.match(modified.stderr, /locally modified/);
  assert.match(fs.readFileSync(customizedOverlay, "utf8"), /another local customization/);

  const commands = fs.readFileSync(log, "utf8");
  assert.match(commands, /omarchy plugin validate/);
  assert.match(commands, /omarchy-shell shell rescanPlugins/);
  assert.match(commands, /omarchy plugin enable pvalletbo\.attached/);
});

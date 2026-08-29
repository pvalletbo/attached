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
      `#!/bin/sh\ninvocation="${command} $*"\nprintf '%s\\n' "$invocation" >> "$ATTACHED_TEST_LOG"\nif [ "$ATTACHED_TEST_FAIL_COMMAND" = "$invocation" ]; then exit 42; fi\n`,
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

  const cleanBindings = "-- existing user binding\n";
  fs.writeFileSync(bindingsPath, cleanBindings);
  for (const failedCommand of [
    "omarchy-shell shell rescanPlugins",
    "omarchy plugin enable pvalletbo.attached"
  ]) {
    const failed = runInstaller({
      ...env,
      ATTACHED_TEST_FAIL_COMMAND: failedCommand
    });
    assert.notEqual(failed.status, 0);
    assert.match(failed.stderr, /restored the previous plugin and bindings/);
    assert.equal(fs.existsSync(destination), false, "failed install must remove plugin files");
    assert.equal(fs.readFileSync(bindingsPath, "utf8"), cleanBindings);
  }

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

  const customizedOverlay = path.join(destination, "Overlay.qml");
  const installedOverlay = fs.readFileSync(customizedOverlay, "utf8");
  fs.writeFileSync(bindingsPath, bindings.replace("Attached sessions", "Changed locally"));
  const modifiedBinding = runInstaller(env);
  assert.notEqual(modifiedBinding.status, 0);
  assert.match(modifiedBinding.stderr, /locally modified managed shortcut block/);
  assert.equal(fs.readFileSync(customizedOverlay, "utf8"), installedOverlay);
  fs.writeFileSync(bindingsPath, bindings);

  const checksumPath = path.join(destination, ".attached-plugin-checksums");
  const completeChecksums = fs.readFileSync(checksumPath, "utf8");
  const firstChecksum = completeChecksums.split("\n")[0] + "\n";
  fs.writeFileSync(checksumPath, firstChecksum + firstChecksum);
  const duplicateProvenance = runInstaller(env);
  assert.notEqual(duplicateProvenance.status, 0);
  assert.match(duplicateProvenance.stderr, /invalid plugin provenance/);

  fs.writeFileSync(checksumPath, firstChecksum);
  fs.appendFileSync(customizedOverlay, "// local customization\n");
  const incompleteProvenance = runInstaller(env);
  assert.notEqual(incompleteProvenance.status, 0);
  assert.match(incompleteProvenance.stderr, /invalid plugin provenance/);
  assert.match(fs.readFileSync(customizedOverlay, "utf8"), /local customization/);

  fs.copyFileSync(path.join(integration, "pvalletbo.attached", "Overlay.qml"), customizedOverlay);
  fs.writeFileSync(checksumPath, completeChecksums);
  const unexpectedPath = path.join(destination, "Unexpected.qml");
  fs.writeFileSync(unexpectedPath, "// unmanaged\n");
  const unexpected = runInstaller(env);
  assert.notEqual(unexpected.status, 0);
  assert.match(unexpected.stderr, /unmanaged entry/);
  assert.match(fs.readFileSync(unexpectedPath, "utf8"), /unmanaged/);
  fs.unlinkSync(unexpectedPath);

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

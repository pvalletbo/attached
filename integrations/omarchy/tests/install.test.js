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

test("installer bootstraps a missing Attached CLI after preflight", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "attached-omarchy-bootstrap-"));
  const home = path.join(root, "home");
  const bin = path.join(root, "bin");
  const localBin = path.join(home, ".local", "bin");
  const log = path.join(root, "commands.log");
  const destination = path.join(
    home,
    ".config",
    "omarchy",
    "plugins",
    "pvalletbo.attached"
  );
  const bindingsPath = path.join(home, ".config", "hypr", "bindings.lua");
  fs.mkdirSync(bin, { recursive: true });

  for (const command of ["omarchy", "omarchy-shell"]) {
    fs.writeFileSync(
      path.join(bin, command),
      `#!/bin/sh\nprintf '${command} %s\\n' "$*" >> "$ATTACHED_TEST_LOG"\n`,
      { mode: 0o755 }
    );
  }
  fs.writeFileSync(
    path.join(bin, "curl"),
    [
      "#!/bin/sh",
      "printf 'curl %s\\n' \"$*\" >> \"$ATTACHED_TEST_LOG\"",
      "if [ \"${ATTACHED_TEST_CURL_FAIL:-}\" = true ]; then exit 22; fi",
      "cat <<'INSTALLER'",
      "#!/bin/sh",
      "set -eu",
      "install -d -m 0755 \"$HOME/.local/bin\"",
      "cat > \"$HOME/.local/bin/attached\" <<'ATTACHED'",
      "#!/bin/sh",
      "printf 'attached test binary\\n'",
      "ATTACHED",
      "chmod 0755 \"$HOME/.local/bin/attached\"",
      "INSTALLER",
      ""
    ].join("\n"),
    { mode: 0o755 }
  );

  const env = {
    ...process.env,
    HOME: home,
    XDG_CONFIG_HOME: path.join(root, "xdg-config"),
    PATH: `${bin}:${localBin}:/usr/bin`,
    ATTACHED_TEST_LOG: log
  };

  fs.mkdirSync(path.dirname(bindingsPath), { recursive: true });
  fs.writeFileSync(bindingsPath, "-- BEGIN Attached session picker\n");
  const rejected = runInstaller(env);
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /partial or duplicate managed shortcut block/);
  assert.doesNotMatch(fs.readFileSync(log, "utf8"), /^curl /m);
  assert.equal(fs.existsSync(localBin), false);
  fs.unlinkSync(bindingsPath);

  const failed = runInstaller({ ...env, ATTACHED_TEST_CURL_FAIL: "true" });
  assert.notEqual(failed.status, 0);
  assert.match(failed.stderr, /Could not install Attached/);
  assert.equal(fs.existsSync(localBin), false);
  assert.equal(fs.existsSync(destination), false);
  assert.equal(fs.existsSync(bindingsPath), false);

  const installed = runInstaller(env);
  assert.equal(installed.status, 0, installed.stderr);
  assert.match(installed.stdout, /Attached is not installed; installing it/);
  assert.ok(fs.statSync(path.join(localBin, "attached")).isFile());
  assert.equal(fs.statSync(path.join(localBin, "attached")).mode & 0o777, 0o755);
  assert.ok(fs.statSync(path.join(destination, "Overlay.qml")).isFile());

  const bootstrapCommands = fs.readFileSync(log, "utf8");
  assert.ok(
    bootstrapCommands.lastIndexOf("omarchy plugin validate")
      < bootstrapCommands.lastIndexOf("curl "),
    "plugin preflight must finish before downloading Attached"
  );
  assert.ok(
    bootstrapCommands.lastIndexOf("curl ")
      < bootstrapCommands.lastIndexOf("omarchy-shell shell rescanPlugins"),
    "Attached must be available before plugin activation"
  );

  const reinstalled = runInstaller(env);
  assert.equal(reinstalled.status, 0, reinstalled.stderr);
  assert.doesNotMatch(reinstalled.stdout, /installing it from/);

  const commands = fs.readFileSync(log, "utf8");
  assert.equal((commands.match(/^curl /gm) || []).length, 2);
  assert.match(
    commands,
    /curl --proto =https --tlsv1\.2 -LsSf https:\/\/install\.attached\.sh/
  );
});

test("installer is idempotent and refuses every destructive or partial write", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "attached-omarchy-install-"));
  const home = path.join(root, "home");
  const bin = path.join(root, "bin");
  const omarchyConfig = path.join(home, ".config");
  const attachedConfig = path.join(root, "xdg-config");
  const log = path.join(root, "commands.log");
  const bindingsPath = path.join(omarchyConfig, "hypr", "bindings.lua");
  const destination = path.join(
    omarchyConfig,
    "omarchy",
    "plugins",
    "pvalletbo.attached"
  );
  const providerConfig = path.join(attachedConfig, "attached", "omarchy.json");
  fs.mkdirSync(path.dirname(bindingsPath), { recursive: true });
  fs.mkdirSync(bin, { recursive: true });

  for (const command of ["omarchy", "omarchy-shell", "attached"]) {
    fs.writeFileSync(
      path.join(bin, command),
      `#!/bin/sh\ninvocation="${command} $*"\nprintf '%s\\n' "$invocation" >> "$ATTACHED_TEST_LOG"\nif [ "$ATTACHED_TEST_FAIL_COMMAND" = "$invocation" ]; then exit 42; fi\n`,
      { mode: 0o755 }
    );
  }

  const env = {
    ...process.env,
    HOME: home,
    XDG_CONFIG_HOME: attachedConfig,
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

  fs.mkdirSync(path.dirname(providerConfig), { recursive: true });
  const providerTarget = path.join(root, "provider-target.json");
  fs.writeFileSync(providerTarget, "user data\n");
  fs.symlinkSync(providerTarget, providerConfig);
  const symlinkedProvider = runInstaller(env);
  assert.notEqual(symlinkedProvider.status, 0);
  assert.match(symlinkedProvider.stderr, /symlinked plugin configuration/);
  assert.equal(fs.readFileSync(providerTarget, "utf8"), "user data\n");
  assert.equal(fs.existsSync(destination), false);
  fs.unlinkSync(providerConfig);

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
    assert.equal(fs.existsSync(providerConfig), false, "failed install must remove new config");
    assert.equal(fs.readFileSync(bindingsPath, "utf8"), cleanBindings);
  }

  const installed = runInstaller(env);
  assert.equal(installed.status, 0, installed.stderr);
  assert.deepEqual(JSON.parse(fs.readFileSync(providerConfig, "utf8")), {
    encryptionPasswordProvider: "password"
  });
  assert.equal(fs.statSync(providerConfig).mode & 0o777, 0o600);

  const customizedProvider = '{\n  "encryptionPasswordProvider": "1password"\n}\n';
  fs.writeFileSync(providerConfig, customizedProvider, { mode: 0o600 });
  const reinstalled = runInstaller(env);
  assert.equal(reinstalled.status, 0, reinstalled.stderr);
  assert.equal(
    fs.readFileSync(providerConfig, "utf8"),
    customizedProvider,
    "installer must preserve the user-owned provider preference"
  );

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

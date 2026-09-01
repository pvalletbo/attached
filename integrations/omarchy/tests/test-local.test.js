"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const integration = path.resolve(__dirname, "..");
const script = path.join(integration, "test-local.sh");

function run(args, env) {
  return spawnSync("bash", [script, ...args], {
    env,
    encoding: "utf8"
  });
}

test("local test script replaces the binary without a backup and reloads the plugin", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "attached-omarchy-local-"));
  const home = path.join(root, "home");
  const config = path.join(home, ".config");
  const bin = path.join(root, "commands");
  const localBin = path.join(home, ".local", "bin");
  const target = path.join(root, "target");
  const log = path.join(root, "commands.log");
  fs.mkdirSync(bin, { recursive: true });

  fs.writeFileSync(
    path.join(bin, "cargo"),
    [
      "#!/bin/sh",
      "printf 'cargo %s\\n' \"$*\" >> \"$ATTACHED_TEST_LOG\"",
      "profile=debug",
      "for argument in \"$@\"; do [ \"$argument\" = --release ] && profile=release; done",
      "mkdir -p \"$CARGO_TARGET_DIR/$profile\"",
      "printf '#!/bin/sh\\nprintf \\\"%s build\\\\n\\\"' \"$profile\" > \"$CARGO_TARGET_DIR/$profile/attached\"",
      "chmod 0755 \"$CARGO_TARGET_DIR/$profile/attached\"",
      ""
    ].join("\n"),
    { mode: 0o755 }
  );

  for (const command of ["omarchy", "omarchy-shell"]) {
    fs.writeFileSync(
      path.join(bin, command),
      `#!/bin/sh\nprintf '${command} %s\\n' "$*" >> "$ATTACHED_TEST_LOG"\n`,
      { mode: 0o755 }
    );
  }

  const env = {
    ...process.env,
    HOME: home,
    XDG_CONFIG_HOME: config,
    CARGO_TARGET_DIR: target,
    ATTACHED_LOCAL_BIN_DIR: localBin,
    ATTACHED_TEST_LOG: log,
    PATH: `${bin}:${process.env.PATH}`
  };

  const debug = run([], env);
  assert.equal(debug.status, 0, debug.stderr);
  const installedBinary = path.join(localBin, "attached");
  assert.match(fs.readFileSync(installedBinary, "utf8"), /debug build/);
  assert.equal(fs.statSync(installedBinary).mode & 0o777, 0o755);
  assert.equal(fs.existsSync(path.join(localBin, "attached.pre-pr")), false);
  assert.ok(
    fs.statSync(path.join(config, "omarchy", "plugins", "pvalletbo.attached", "Overlay.qml"))
      .isFile()
  );
  assert.deepEqual(
    JSON.parse(fs.readFileSync(path.join(config, "attached", "omarchy.json"), "utf8")),
    { encryptionPasswordProvider: "password" }
  );

  const release = run(["--release"], env);
  assert.equal(release.status, 0, release.stderr);
  assert.match(fs.readFileSync(installedBinary, "utf8"), /release build/);
  assert.equal(fs.existsSync(path.join(localBin, "attached.pre-pr")), false);

  const commands = fs.readFileSync(log, "utf8");
  assert.match(commands, /cargo build --locked --package attached/);
  assert.match(commands, /cargo build --locked --package attached --release/);
  assert.match(commands, /omarchy-shell shell rescanPlugins/);
  assert.match(commands, /omarchy plugin enable pvalletbo\.attached/);

  const invalid = run(["--unknown"], env);
  assert.equal(invalid.status, 2);
  assert.match(invalid.stderr, /Usage: test-local\.sh \[--release\]/);
});

import { mkdirSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const webDirectory = path.dirname(fileURLToPath(import.meta.url));
const experimentalDirectory = path.dirname(webDirectory);
const repositoryDirectory = path.dirname(experimentalDirectory);
const targetDirectory = path.join(
  repositoryDirectory,
  "target/wasm32-unknown-unknown/release",
);

function supportsWasm(command) {
  return spawnSync(
    command,
    ["--target=wasm32-unknown-unknown", "-x", "c", "-c", "-o", "/dev/null", "-"],
    { input: "int herdr_wasm_probe;\n", stdio: ["pipe", "ignore", "ignore"] },
  ).status === 0;
}

function run(command, arguments_, environment = process.env) {
  const result = spawnSync(command, arguments_, {
    cwd: repositoryDirectory,
    env: environment,
    stdio: "inherit",
  });
  if (result.status !== 0) process.exit(result.status ?? 1);
}

const configuredCompiler = process.env.CC_wasm32_unknown_unknown;
const wasmCompiler = configuredCompiler !== undefined
  ? configuredCompiler
  : [
      "clang-18",
      "/opt/homebrew/opt/llvm/bin/clang",
      "/usr/local/opt/llvm/bin/clang",
      "clang",
    ].find(supportsWasm);
if (wasmCompiler === undefined || !supportsWasm(wasmCompiler)) {
  throw new Error(
    "building browser WASM requires LLVM clang with wasm32 support; install LLVM or set CC_wasm32_unknown_unknown",
  );
}

run(
  "cargo",
  [
    "build",
    "--locked",
    "--manifest-path",
    path.join(repositoryDirectory, "Cargo.toml"),
    "-p",
    "herdr-tui-protocol",
    "-p",
    "attached-browser-sync",
    "-p",
    "attached-browser-iroh",
    "--target",
    "wasm32-unknown-unknown",
    "--release",
  ],
  { ...process.env, CC_wasm32_unknown_unknown: wasmCompiler },
);

const protocolBindingsDirectory = path.join(webDirectory, "src/protocol-bindings");
mkdirSync(protocolBindingsDirectory, { recursive: true });
run("wasm-bindgen", [
  "--target",
  "web",
  "--out-dir",
  protocolBindingsDirectory,
  "--out-name",
  "herdr_tui_protocol",
  path.join(targetDirectory, "herdr_tui_protocol.wasm"),
]);

const syncBindingsDirectory = path.join(webDirectory, "src/sync-bindings");
mkdirSync(syncBindingsDirectory, { recursive: true });
run("wasm-bindgen", [
  "--target",
  "web",
  "--out-dir",
  syncBindingsDirectory,
  "--out-name",
  "attached_browser_sync",
  path.join(targetDirectory, "attached_browser_sync.wasm"),
]);

const bindingsDirectory = path.join(webDirectory, "src/iroh-bindings");
mkdirSync(bindingsDirectory, { recursive: true });
run("wasm-bindgen", [
  "--target",
  "web",
  "--out-dir",
  bindingsDirectory,
  "--out-name",
  "attached_browser_iroh",
  path.join(targetDirectory, "attached_browser_iroh.wasm"),
]);

console.log(`Herdr protocol bindings: ${protocolBindingsDirectory}`);
console.log(`Browser sync bindings: ${syncBindingsDirectory}`);
console.log(`Browser Iroh bindings: ${bindingsDirectory}`);

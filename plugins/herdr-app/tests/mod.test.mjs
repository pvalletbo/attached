// No app, network, SSH credentials or third-party JS packages are used here.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("../mods/attached-discovery/main.js", import.meta.url), "utf8");
const program = source.replace(/^import .*;\n/gm, "")
  .replace("export default class AttachedDiscovery", "class AttachedDiscovery")
  + "\nglobalThis.Mod = AttachedDiscovery;";

function fixture() {
  const state = new Map();
  const calls = [], notices = [], timers = [], tasks = [], clicks = new Map();
  let response = { code: 0, stdout: JSON.stringify({ running: true, managed: 2, notices: [] }), stderr: "" };
  let notifications = 0;
  function element() {
    let id;
    const proxy = new Proxy({}, {
      get(_target, method) {
        return (...args) => {
          if (method === "id") id = args[0];
          if (method === "on_click") clicks.set(id, args[0]);
          if (method === "when" && args[0]) return args[1](proxy);
          return proxy;
        };
      },
    });
    return proxy;
  }
  const cx = {
    spawn(task) { tasks.push(task({ notify() { notifications++; } })); },
    timer: { every(ms, callback) { timers.push({ ms, callback }); } },
  };
  const context = vm.createContext({
    View: class {}, div: element, v_flex: element, h_flex: element,
    appHome: () => "/app", theme: () => ({}),
    shared: (key) => state.get(key), setShared: (key, value) => state.set(key, value),
    notify: (notice) => notices.push(notice),
    exec: async (command, args) => { calls.push({ command, args: [...args] }); return response; },
  });
  vm.runInContext(program, context);
  const mod = new context.Mod();
  return {
    mod, cx, state, calls, notices, timers, clicks,
    response(value) { response = value; },
    async flush() { while (tasks.length) await Promise.all(tasks.splice(0)); },
    notifications: () => notifications,
  };
}

test("initialization renews the lease without installing cores and polls data gently", async () => {
  const f = fixture();
  assert.equal(f.calls.length, 0, "no top-level side effects");
  f.mod.init({}, f.cx);
  f.mod.refresh(f.cx); // overlapping refresh must not spawn another task
  await f.flush();
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].command, "/app/mods/attached-discovery/worker");
  assert.deepEqual(f.calls[0].args, ["app-heartbeat", "/app/data/attached-discovery"]);
  assert.equal(f.timers[0].ms, 15000);
  assert.equal(f.notifications(), 1);
  assert.equal(f.mod.busy, false);
  assert.ok(f.mod.render());
});

test("core installation/upgrades require an explicit persistent toggle", async () => {
  const f = fixture();
  f.mod.init({}, f.cx);
  await f.flush();
  f.mod.render();
  f.clicks.get("attached-install")({}, f.cx);
  await f.flush();
  assert.equal(f.state.get("attached.discovery.install-core"), true);
  assert.deepEqual(f.calls.at(-1).args, ["app-heartbeat", "/app/data/attached-discovery", "--install-core"]);
});

test("pause persists and stops renewal without removing machines", async () => {
  const f = fixture();
  f.mod.init({}, f.cx);
  await f.flush();
  f.mod.render();
  f.clicks.get("attached-toggle")({}, f.cx);
  await f.flush();
  assert.equal(f.state.get("attached.discovery.enabled"), false);
  assert.deepEqual(f.calls.at(-1).args, ["app-pause", "/app/data/attached-discovery"]);
});

test("notifications are deduplicated across refreshes and panel copies", async () => {
  const f = fixture();
  f.response({ code: 0, stdout: JSON.stringify({ running: true, managed: 1, notices: [{ id: "one", label: "Office" }] }) });
  f.mod.init({}, f.cx);
  await f.flush();
  f.mod.refresh(f.cx);
  await f.flush();
  assert.equal(f.notices.length, 1);
  assert.match(f.notices[0].body, /Office/);
  f.mod.init({}, f.cx); // a reloaded copy sees the shared deduplication state
  await f.flush();
  assert.equal(f.notices.length, 1);
});

test("worker errors are visible and do not wedge subsequent refreshes", async () => {
  const f = fixture();
  f.response({ code: 1, stderr: "invalid discovery state" });
  f.mod.init({}, f.cx);
  await f.flush();
  assert.match(f.mod.error, /invalid discovery state/);
  assert.equal(f.mod.busy, false);
  assert.ok(f.mod.render());
  f.response({ code: 0, stdout: JSON.stringify({ running: false, managed: 0, notices: [] }) });
  f.mod.refresh(f.cx);
  await f.flush();
  assert.equal(f.mod.error, null);
});

test("manifest opens on demand as a popup and never auto-docks a panel", async () => {
  const manifest = JSON.parse(await readFile(new URL("../mods/attached-discovery/mod.json", import.meta.url), "utf8"));
  assert.equal(manifest.place, "none");
  assert.equal(manifest.overlay.kind, "popup");
  assert.ok(manifest.overlay.width >= 900);
  assert.ok(manifest.overlay.height >= 124);
});

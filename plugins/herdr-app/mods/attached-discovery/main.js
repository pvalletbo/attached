// Build: cargo build --release --locked -p attached-herdr-plugin
// Install: target/release/attached-herdr-plugin app-install "$HOME/.config/herdr-app"
// Open on demand: herdr-app do mod.open --name attached-discovery
// Closing the popup stops renewal unless another copy remains loaded.
// A personal layout block or mod tab is optional; see the bundled README.md.
// This mod runs programs (hc, ssh, attached) through its bundled Rust worker,
// reads ~/.ssh/attached/discovery.json, and writes only its own app data.
// It enrolls reachable publishers; core installs/upgrades require explicit opt-in.
// The worker renews/reuses the exporter without reading credentials in JavaScript.
// No shipped layout/mod is modified. Add this panel to each layout that should
// run discovery; hiding it keeps it alive, removing/switching away stops renewal.
// On unload/quit its lease expires after 90s without renewal, then it stops
// only its own exporter (allowing graceful cleanup). Saved
// machines remain. Removal forgets a registration, never kills remote terminals.
import { View, div } from "gpui-kit";
import { v_flex, h_flex } from "gpui-base";
import { appHome, exec, notify, shared, setShared, theme } from "herdr";

const ENABLED = "attached.discovery.enabled";
const INSTALL = "attached.discovery.install-core";
const SEEN = "attached.discovery.notices";

export default class AttachedDiscovery extends View {
  init(_props, cx) {
    this.busy = false;
    this.status = null;
    this.error = null;
    this.refresh(cx);
    // Only data polling, not animation. The detached worker does the slow SSH
    // work; the app's 30-second exec deadline cannot interrupt an enrollment.
    cx.timer.every(15000, (cx) => this.refresh(cx));
  }

  refresh(cx) {
    if (this.busy) return;
    this.busy = true;
    cx.spawn(async (cx) => {
      try {
        const enabled = shared(ENABLED) !== false;
        const args = [enabled ? "app-heartbeat" : "app-pause", `${appHome()}/data/attached-discovery`];
        if (enabled && shared(INSTALL) === true) args.push("--install-core");
        const result = await exec(`${appHome()}/mods/attached-discovery/worker`, args);
        if (result.code !== 0) throw new Error(result.stderr || result.stdout || "Discovery worker failed");
        this.status = JSON.parse(result.stdout);
        this.error = null;
        const seen = shared(SEEN) ?? [];
        const notices = this.status.notices ?? [];
        // Publish deduplication before notifying, so a second panel/window
        // reading the same worker status cannot toast the same addition twice.
        setShared(SEEN, [...new Set([...seen, ...notices.map((n) => n.id)])].slice(-64));
        if (enabled) {
          for (const notice of notices) {
            if (!seen.includes(notice.id)) {
              notify({ title: "Attached machine added", body: `${notice.label} is now available in Machines.`, level: "info" });
            }
          }
        }
      } catch (error) {
        this.error = String(error);
      } finally {
        this.busy = false;
        cx.notify();
      }
    });
  }

  button(id, text, action, t) {
    return div().id(id).px(9).py(4).rounded(5).bg(t.raised)
      .text_color(t.foreground).cursor_pointer().hover((s) => s.bg(t.hover))
      .on_click((_event, cx) => action(cx)).child(text);
  }

  render() {
    const t = theme();
    const enabled = shared(ENABLED) !== false;
    const install = shared(INSTALL) === true;
    const message = this.error ?? this.status?.error;
    return v_flex().size_full().p(10).gap(5).bg(t.chrome).text_size(12).text_color(t.muted)
      .child(h_flex().items_center().gap(8)
        .child(div().font_semibold().text_color(t.foreground).child("Attached machines"))
        .child(div().flex_1().child(!enabled ? "Paused" : this.status?.running ? `${this.status.managed} auto-enrolled` : "Starting discovery…"))
        .child(this.button("attached-refresh", "Refresh", (cx) => this.refresh(cx), t))
        .child(this.button("attached-toggle", enabled ? "Pause" : "Resume", (cx) => {
          setShared(ENABLED, !enabled);
          this.refresh(cx);
        }, t)))
      .child(h_flex().items_center().gap(8)
        .child(this.button("attached-install", install ? "Core installs/upgrades: ON" : "Core installs/upgrades: OFF", (cx) => {
          setShared(INSTALL, !install);
          this.refresh(cx);
        }, t))
        .child(div().child("Only auto-enrolled machines are removed, after 3 complete missing checks.")))
      .when(Boolean(message), (el) => el.child(div().text_color(t.blocked).truncate().child(message)))
      .child(div().text_size(11).text_color(t.dim).child("Polls every 30s while loaded · requires compatible remote hc unless installs are ON · logs: data/attached-discovery"));
  }
}

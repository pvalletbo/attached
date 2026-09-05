import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

const extensionRoot = join(__dirname, "..");
const manifest = JSON.parse(readFileSync(join(extensionRoot, "package.json"), "utf8")) as {
  platforms: string[];
  commands: Array<{ name: string; mode: string }>;
  preferences: Array<{ name: string; default?: string }>;
  icon: string;
};

describe("Raycast extension contract", () => {
  it("registers the macOS session picker entry point", () => {
    expect(manifest.platforms).toEqual(["macOS"]);
    expect(manifest.commands).toContainEqual({
      name: "search-sessions",
      title: "Search Sessions",
      subtitle: "Attached",
      description: "Search synchronized Attached sessions and connect in Terminal.",
      mode: "view",
    });
    expect(existsSync(join(extensionRoot, "src", "search-sessions.tsx"))).toBe(true);
  });

  it("defaults to an ephemeral typed password instead of 1Password", () => {
    expect(manifest.preferences.find((preference) => preference.name === "encryptionPasswordProvider")?.default).toBe(
      "password",
    );
  });

  it("ships the required 512px PNG icon", () => {
    const icon = readFileSync(join(extensionRoot, "assets", manifest.icon));

    expect(icon.subarray(1, 4).toString("ascii")).toBe("PNG");
    expect(icon.readUInt32BE(16)).toBe(512);
    expect(icon.readUInt32BE(20)).toBe(512);
  });
});

import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { describe, expect, it } from "vitest";

import { buildAttachCommand, quoteShellArgument, terminalInvocation } from "./terminal";

const execFileAsync = promisify(execFile);

describe("quoteShellArgument", () => {
  it("quotes spaces, substitutions, and apostrophes as literal text", () => {
    expect(quoteShellArgument("session with '$HOME' $(touch nope)")).toBe(
      `'session with '"'"'$HOME'"'"' $(touch nope)'`,
    );
  });

  it("rejects values that cannot be represented in an argv element", () => {
    expect(() => quoteShellArgument("bad\0value")).toThrow("null byte");
  });
});

describe("buildAttachCommand", () => {
  it("quotes every shell word and adds 1Password only when configured", () => {
    expect(buildAttachCommand("/Users/me/My Tools/attached", "password", "office/deep work")).toBe(
      "exec '/Users/me/My Tools/attached' 'attach' 'office/deep work'",
    );
    expect(buildAttachCommand("/opt/homebrew/bin/attached", "1password", "office/work")).toBe(
      "exec '/opt/homebrew/bin/attached' '--use-1password' 'attach' 'office/work'",
    );
  });

  it("does not let a synchronized target become shell syntax", async () => {
    const root = await mkdtemp(join(tmpdir(), "attached-terminal-test-"));
    const marker = join(root, "injected");
    const target = `host/' " $(touch ${marker}) ; session`;

    try {
      const command = buildAttachCommand("/bin/echo", "password", target);
      const { stdout } = await execFileAsync("/bin/sh", ["-c", command], { encoding: "utf8" });

      expect(stdout).toBe(`attach ${target}\n`);
      await expect(import("node:fs/promises").then(({ access }) => access(marker))).rejects.toThrow();
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});

describe("terminalInvocation", () => {
  it("passes the shell command as a separate osascript argument", () => {
    const command = "exec '/path/attached' 'attach' 'host/session'";
    const invocation = terminalInvocation(command);

    expect(invocation.executable).toBe("/usr/bin/osascript");
    expect(invocation.arguments.slice(-2)).toEqual(["--", command]);
    expect(invocation.arguments.slice(0, -1).join("\n")).not.toContain("host/session");
  });
});

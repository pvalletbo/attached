import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import {
  attachArguments,
  AttachedNotFoundError,
  catalogArguments,
  CatalogCommandError,
  catalogExitReason,
  InvalidAttachedPathError,
  loadSessionCatalog,
  resolveAttachedExecutable,
} from "./attached";

const temporaryDirectories: string[] = [];

async function shellProgram(body: string): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "attached-raycast-test-"));
  temporaryDirectories.push(root);
  const executable = join(root, "fake-attached");
  await writeFile(executable, `#!/bin/sh\nset -eu\n${body}\n`, "utf8");
  await chmod(executable, 0o700);
  return executable;
}

afterEach(async () => {
  await Promise.all(temporaryDirectories.splice(0).map((path) => rm(path, { recursive: true, force: true })));
});

describe("Attached command construction", () => {
  it("keeps passwords out of arguments", () => {
    expect(catalogArguments("password")).toEqual(["sessions", "--password-stdin"]);
    expect(catalogArguments("1password")).toEqual(["--use-1password", "sessions"]);
  });

  it("keeps synchronized targets in one argv element", () => {
    const target = "host/session with 'quotes'; touch nope";
    expect(attachArguments("password", target)).toEqual(["attach", target]);
    expect(attachArguments("1password", target)).toEqual(["--use-1password", "attach", target]);
  });
});

describe("resolveAttachedExecutable", () => {
  it("prefers an explicitly configured executable", () => {
    const result = resolveAttachedExecutable(
      "~/custom/attached",
      (path) => path === "/Users/test/custom/attached",
      "/Users/test",
    );

    expect(result).toBe("/Users/test/custom/attached");
  });

  it("falls back to standard Attached install locations", () => {
    const result = resolveAttachedExecutable(
      undefined,
      (path) => path === "/Users/test/.local/bin/attached",
      "/Users/test",
    );

    expect(result).toBe("/Users/test/.local/bin/attached");
  });

  it("rejects a relative preference", () => {
    expect(() => resolveAttachedExecutable("bin/attached", () => true, "/Users/test")).toThrow(
      InvalidAttachedPathError,
    );
  });

  it("reports when no candidate is executable", () => {
    expect(() => resolveAttachedExecutable(undefined, () => false, "/Users/test")).toThrow(AttachedNotFoundError);
  });
});

describe("loadSessionCatalog", () => {
  it("writes a password through stdin and parses stdout", async () => {
    const executable = await shellProgram(`
[ "$1" = "sessions" ]
[ "$2" = "--password-stdin" ]
IFS= read -r password
[ "$password" = "correct horse" ]
printf '%s\\n' '[{"target":"office/work","host":"office","session":"work","attachedVersion":[0,3,1],"herdrVersion":[0,9,0],"publishedAt":null}]'
`);
    const password = Buffer.from("correct horse", "utf8");

    const sessions = await loadSessionCatalog(executable, "password", password);

    expect(sessions).toHaveLength(1);
    expect(sessions[0]?.target).toBe("office/work");
    expect(password.every((byte) => byte === 0)).toBe(true);
  });

  it("uses the noninteractive 1Password argv", async () => {
    const executable = await shellProgram(`
[ "$1" = "--use-1password" ]
[ "$2" = "sessions" ]
printf '%s\\n' '[]'
`);

    await expect(loadSessionCatalog(executable, "1password")).resolves.toEqual([]);
  });

  it("classifies authentication failures without exposing stderr", async () => {
    const executable = await shellProgram(`
printf '%s\\n' 'encrypted local secret authentication failed: sensitive detail' >&2
exit 1
`);

    const error = await loadSessionCatalog(executable, "password", Buffer.from("wrong"))
      .then(() => undefined)
      .catch((reason: unknown) => reason);

    expect(error).toBeInstanceOf(CatalogCommandError);
    expect(error).toMatchObject({ kind: "exit", exitReason: "authentication", exitCode: 1 });
    expect(String(error)).not.toContain("sensitive detail");
    expect(String(error)).not.toContain("wrong");
  });

  it("terminates a refresh that exceeds its deadline", async () => {
    const executable = await shellProgram("sleep 5");

    await expect(
      loadSessionCatalog(executable, "1password", undefined, { timeoutMilliseconds: 20 }),
    ).rejects.toMatchObject({ kind: "timeout" });
  });

  it("rejects output above the configured bound", async () => {
    const executable = await shellProgram("printf '0123456789'");

    await expect(loadSessionCatalog(executable, "1password", undefined, { maxOutputBytes: 5 })).rejects.toMatchObject({
      kind: "too-large",
    });
  });
});

describe("catalogExitReason", () => {
  it("recognizes provider-specific failures", () => {
    expect(catalogExitReason("1Password CLI is not signed in", "1password")).toBe("one-password");
    expect(catalogExitReason("encrypted local secret authentication failed", "password")).toBe("authentication");
    expect(catalogExitReason("Usage: attached sessions [OPTIONS] <COMMAND>", "password")).toBe("unsupported");
    expect(catalogExitReason("network unavailable", "password")).toBe("generic");
  });
});

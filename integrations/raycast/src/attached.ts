import { spawn } from "node:child_process";
import { accessSync, constants } from "node:fs";
import { homedir } from "node:os";
import { delimiter, isAbsolute } from "node:path";

import { AttachedSession, CatalogValidationError, parseCatalog } from "./catalog";

export type EncryptionPasswordProvider = "password" | "1password";

export const MAX_PASSWORD_BYTES = 1_024;
const DEFAULT_TIMEOUT_MILLISECONDS = 15_000;
const DEFAULT_MAX_OUTPUT_BYTES = 4 * 1_024 * 1_024;
const MAX_DIAGNOSTIC_BYTES = 64 * 1_024;
const FORCE_KILL_DELAY_MILLISECONDS = 250;

export type CatalogExitReason = "authentication" | "one-password" | "unsupported" | "generic";
export type CatalogCommandErrorKind = "aborted" | "launch" | "timeout" | "too-large" | "exit";

export class AttachedNotFoundError extends Error {
  constructor(readonly searchedPaths: string[]) {
    super("Attached executable was not found");
    this.name = "AttachedNotFoundError";
  }
}

export class InvalidAttachedPathError extends Error {
  constructor() {
    super("The Attached executable preference must be an absolute path");
    this.name = "InvalidAttachedPathError";
  }
}

export class CatalogCommandError extends Error {
  constructor(
    readonly kind: CatalogCommandErrorKind,
    readonly provider: EncryptionPasswordProvider,
    readonly exitReason: CatalogExitReason = "generic",
    readonly exitCode: number | null = null,
    options?: ErrorOptions,
  ) {
    super(catalogCommandErrorMessage(kind), options);
    this.name = "CatalogCommandError";
  }
}

function catalogCommandErrorMessage(kind: CatalogCommandErrorKind): string {
  switch (kind) {
    case "aborted":
      return "Attached session refresh was cancelled";
    case "launch":
      return "Attached could not be started";
    case "timeout":
      return "Attached session refresh timed out";
    case "too-large":
      return "Attached returned too much session data";
    case "exit":
      return "Attached could not refresh sessions";
  }
}

export function catalogArguments(provider: EncryptionPasswordProvider): string[] {
  return provider === "1password" ? ["--use-1password", "sessions"] : ["sessions", "--password-stdin"];
}

export function attachArguments(provider: EncryptionPasswordProvider, target: string): string[] {
  if (target.length === 0 || target.includes("\0")) {
    throw new Error("Cannot launch an invalid session target");
  }
  return provider === "1password" ? ["--use-1password", "attach", target] : ["attach", target];
}

export function attachedExecutableCandidates(preferredPath: string | undefined, home = homedir()): string[] {
  const preferred = preferredPath?.trim();
  const candidates = [
    preferred ? expandHome(preferred, home) : undefined,
    `${home}/.local/bin/attached`,
    `${home}/.cargo/bin/attached`,
    "/opt/homebrew/bin/attached",
    "/usr/local/bin/attached",
  ].filter((candidate): candidate is string => candidate !== undefined);

  return [...new Set(candidates)];
}

export function resolveAttachedExecutable(
  preferredPath: string | undefined,
  isExecutable: (path: string) => boolean = executableExists,
  home = homedir(),
): string {
  const candidates = attachedExecutableCandidates(preferredPath, home);
  const preferred = preferredPath?.trim();
  if (preferred && !isAbsolute(expandHome(preferred, home))) {
    throw new InvalidAttachedPathError();
  }

  const executable = candidates.find(isExecutable);
  if (executable === undefined) {
    throw new AttachedNotFoundError(candidates);
  }
  return executable;
}

function expandHome(path: string, home: string): string {
  return path === "~" ? home : path.startsWith("~/") ? `${home}/${path.slice(2)}` : path;
}

function executableExists(path: string): boolean {
  try {
    accessSync(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export type LoadCatalogOptions = {
  signal?: AbortSignal;
  timeoutMilliseconds?: number;
  maxOutputBytes?: number;
};

export async function loadSessionCatalog(
  executable: string,
  provider: EncryptionPasswordProvider,
  password?: Buffer,
  options: LoadCatalogOptions = {},
): Promise<AttachedSession[]> {
  validatePasswordInput(provider, password);
  if (options.signal?.aborted) {
    throw new CatalogCommandError("aborted", provider);
  }

  const timeoutMilliseconds = options.timeoutMilliseconds ?? DEFAULT_TIMEOUT_MILLISECONDS;
  const maxOutputBytes = options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;

  return new Promise((resolve, reject) => {
    const child = spawn(executable, catalogArguments(provider), {
      env: attachedEnvironment(),
      stdio: ["pipe", "pipe", "pipe"],
    });
    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let termination: CatalogCommandErrorKind | undefined;
    let settled = false;
    let forceKillTimer: NodeJS.Timeout | undefined;

    const timeout = setTimeout(() => terminate("timeout"), timeoutMilliseconds);

    function cleanup() {
      clearTimeout(timeout);
      if (forceKillTimer !== undefined) {
        clearTimeout(forceKillTimer);
      }
      options.signal?.removeEventListener("abort", abort);
      password?.fill(0);
    }

    function finish<T>(callback: (value: T) => void, value: T) {
      if (settled) {
        return;
      }
      settled = true;
      cleanup();
      callback(value);
    }

    function terminate(reason: CatalogCommandErrorKind) {
      if (termination !== undefined || settled) {
        return;
      }
      termination = reason;
      child.kill("SIGTERM");
      forceKillTimer = setTimeout(() => child.kill("SIGKILL"), FORCE_KILL_DELAY_MILLISECONDS);
      forceKillTimer.unref();
    }

    function abort() {
      terminate("aborted");
    }

    options.signal?.addEventListener("abort", abort, { once: true });

    child.stdout.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.byteLength;
      if (stdoutBytes > maxOutputBytes) {
        terminate("too-large");
        return;
      }
      stdoutChunks.push(chunk);
    });

    child.stderr.on("data", (chunk: Buffer) => {
      if (stderrBytes >= MAX_DIAGNOSTIC_BYTES) {
        return;
      }
      const remaining = MAX_DIAGNOSTIC_BYTES - stderrBytes;
      const bounded = chunk.subarray(0, remaining);
      stderrChunks.push(bounded);
      stderrBytes += bounded.byteLength;
    });

    // A fast failure can close stdin before the password write completes. The
    // exit status below is the useful result; consuming this error also avoids
    // an unhandled EPIPE without ever logging secret input.
    child.stdin.on("error", () => undefined);
    if (provider === "password" && password !== undefined) {
      child.stdin.write(password, () => password.fill(0));
      child.stdin.end("\n");
    } else {
      child.stdin.end();
    }

    child.once("error", (error: NodeJS.ErrnoException) => {
      finish(reject, new CatalogCommandError("launch", provider, "generic", null, { cause: error }));
    });

    child.once("close", (exitCode) => {
      if (termination !== undefined) {
        finish(reject, new CatalogCommandError(termination, provider));
        return;
      }
      if (exitCode !== 0) {
        const stderr = Buffer.concat(stderrChunks).toString("utf8");
        finish(reject, new CatalogCommandError("exit", provider, catalogExitReason(stderr, provider), exitCode));
        return;
      }

      const stdout = Buffer.concat(stdoutChunks).toString("utf8");
      try {
        finish(resolve, parseCatalog(stdout));
      } catch (error) {
        if (error instanceof CatalogValidationError) {
          finish(reject, error);
        } else {
          finish(reject, new CatalogValidationError("Attached returned an invalid session catalog", { cause: error }));
        }
      }
    });
  });
}

function validatePasswordInput(provider: EncryptionPasswordProvider, password: Buffer | undefined) {
  if (provider !== "password") {
    return;
  }
  if (password === undefined || password.byteLength === 0) {
    throw new Error("The encryption password cannot be empty");
  }
  if (password.byteLength > MAX_PASSWORD_BYTES) {
    throw new Error(`The encryption password exceeds ${MAX_PASSWORD_BYTES} bytes`);
  }
}

export function catalogExitReason(stderr: string, provider: EncryptionPasswordProvider): CatalogExitReason {
  const detail = stderr.toLocaleLowerCase();
  if (provider === "1password" && detail.includes("1password")) {
    return "one-password";
  }
  if (detail.includes("encrypted local secret authentication failed")) {
    return "authentication";
  }
  if (
    detail.includes("usage: attached sessions [options] <command>") ||
    detail.includes("unexpected argument '--password-stdin'") ||
    detail.includes("requires a subcommand")
  ) {
    return "unsupported";
  }
  return "generic";
}

function attachedEnvironment(): NodeJS.ProcessEnv {
  const commonPaths = [
    `${homedir()}/.local/bin`,
    `${homedir()}/.cargo/bin`,
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
  ];
  const inheritedPaths = (process.env.PATH ?? "").split(delimiter).filter(Boolean);
  return {
    ...process.env,
    PATH: [...new Set([...commonPaths, ...inheritedPaths])].join(delimiter),
  };
}

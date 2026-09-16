import { execFile } from "node:child_process";

import { attachArguments, EncryptionPasswordProvider } from "./attached";

const TERMINAL_JXA = `
function run(argv) {
  const terminal = Application("com.apple.Terminal");
  terminal.activate();
  terminal.doScript(argv[0]);
}
`;

export class TerminalLaunchError extends Error {
  constructor(options?: ErrorOptions) {
    super("Terminal could not be opened", options);
    this.name = "TerminalLaunchError";
  }
}

export function quoteShellArgument(value: string): string {
  if (value.includes("\0")) {
    throw new Error("Shell arguments cannot contain a null byte");
  }
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

export function buildAttachCommand(executable: string, provider: EncryptionPasswordProvider, target: string): string {
  return `exec ${[executable, ...attachArguments(provider, target)].map(quoteShellArgument).join(" ")}`;
}

export function terminalInvocation(command: string): { executable: string; arguments: string[] } {
  return {
    executable: "/usr/bin/osascript",
    arguments: ["-l", "JavaScript", "-e", TERMINAL_JXA, "--", command],
  };
}

export async function launchAttachedSession(
  executable: string,
  provider: EncryptionPasswordProvider,
  target: string,
): Promise<void> {
  const invocation = terminalInvocation(buildAttachCommand(executable, provider, target));
  await new Promise<void>((resolve, reject) => {
    execFile(invocation.executable, invocation.arguments, { timeout: 5_000, maxBuffer: 64 * 1_024 }, (error) => {
      if (error) {
        reject(new TerminalLaunchError({ cause: error }));
        return;
      }
      resolve();
    });
  });
}

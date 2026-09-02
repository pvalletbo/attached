const MAX_COMMAND_BYTES = 4096;
const MAX_OUTPUT_BYTES = 32 * 1024;
const COMPUTER_COMMAND_ENV = "ATTACHED_COMPUTER_COMMAND";
const COMPUTER_WRAPPER =
  `setpriv --no-new-privs --reuid=10001 --regid=10001 --clear-groups ` +
  `bash -o pipefail -c 'eval -- "$${COMPUTER_COMMAND_ENV}" ` +
  `> >(head -c ${MAX_OUTPUT_BYTES}) 2> >(head -c ${MAX_OUTPUT_BYTES} >&2)'`;

/**
 * @param {Request} request
 * @param {string | undefined} expectedToken
 */
export function isAuthorized(request, expectedToken) {
  if (!expectedToken) return false;
  return request.headers.get("authorization") === `Bearer ${expectedToken}`;
}

/**
 * @param {unknown} value
 * @param {number} [status]
 */
export function json(value, status = 200) {
  return Response.json(value, {
    status,
    headers: { "cache-control": "no-store" },
  });
}

/** @param {unknown} error */
export function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

/** @param {string} pathname */
export function lastPathSegment(pathname) {
  return pathname.split("/").filter(Boolean).at(-1) ?? "";
}

/**
 * @param {string} prefix
 * @param {string} agentName
 */
export function deriveHostLabel(prefix, agentName) {
  const normalized = `${prefix}-${agentName}`
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^[^a-z0-9]+/, "");
  return (normalized || "cloudflare-agent").slice(0, 64);
}

/** @param {unknown} command */
export function validateCommand(command) {
  if (typeof command !== "string") {
    throw new TypeError("command must be a string");
  }
  const trimmed = command.trim();
  if (!trimmed) throw new TypeError("command must not be empty");
  if (trimmed.includes("\0")) throw new TypeError("command must not contain NUL");
  if (new TextEncoder().encode(trimmed).byteLength > MAX_COMMAND_BYTES) {
    throw new TypeError(`command must be at most ${MAX_COMMAND_BYTES} bytes`);
  }
  return trimmed;
}

/** @param {unknown} command */
export function computerInvocation(command) {
  const validated = validateCommand(command);
  return {
    command: COMPUTER_WRAPPER,
    env: { [COMPUTER_COMMAND_ENV]: validated },
  };
}

/** @param {string} output */
export function truncateOutput(output) {
  const bytes = new TextEncoder().encode(output);
  if (bytes.byteLength <= MAX_OUTPUT_BYTES) return output;
  return `${new TextDecoder().decode(bytes.slice(0, MAX_OUTPUT_BYTES))}\n[truncated]`;
}

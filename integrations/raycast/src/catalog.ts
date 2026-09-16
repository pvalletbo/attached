export const MAX_SESSION_COUNT = 4_096;

type VersionTuple = [number, number, number];

export type AttachedSession = {
  target: string;
  host: string;
  session: string;
  attachedVersion: VersionTuple | null;
  herdrVersion: VersionTuple;
  publishedAt: string | null;
};

export class CatalogValidationError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "CatalogValidationError";
  }
}

export function parseCatalog(raw: string): AttachedSession[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new CatalogValidationError("Attached did not return valid JSON", { cause: error });
  }

  if (!Array.isArray(parsed)) {
    throw new CatalogValidationError("Attached session catalog must be a JSON array");
  }
  if (parsed.length > MAX_SESSION_COUNT) {
    throw new CatalogValidationError("Attached returned too many sessions");
  }

  const sessions = parsed.map((value, index) => parseSession(value, index + 1));
  if (new Set(sessions.map((session) => session.target)).size !== sessions.length) {
    throw new CatalogValidationError("Attached returned duplicate session targets");
  }
  return sessions;
}

function parseSession(value: unknown, rowNumber: number): AttachedSession {
  if (!isRecord(value)) {
    throw new CatalogValidationError(`session row ${rowNumber} must be an object`);
  }

  const target = parseText(value.target, "target", rowNumber);
  const host = parseText(value.host, "host", rowNumber);
  const session = parseText(value.session, "session", rowNumber);
  if (target !== `${host}/${session}`) {
    throw new CatalogValidationError(`session row ${rowNumber} has an invalid target`);
  }

  const attachedVersion = parseVersion(value.attachedVersion, "attachedVersion", rowNumber, true);
  const herdrVersion = parseVersion(value.herdrVersion, "herdrVersion", rowNumber, false);
  const publishedAt = parsePublishedAt(value.publishedAt, rowNumber);

  return {
    target,
    host,
    session,
    attachedVersion,
    herdrVersion,
    publishedAt,
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseText(value: unknown, field: string, rowNumber: number): string {
  if (typeof value !== "string" || value.length === 0 || /\p{Cc}/u.test(value)) {
    throw new CatalogValidationError(`session row ${rowNumber} has an invalid ${field}`);
  }
  return value;
}

function parseVersion(value: unknown, field: string, rowNumber: number, optional: true): VersionTuple | null;
function parseVersion(value: unknown, field: string, rowNumber: number, optional: false): VersionTuple;
function parseVersion(value: unknown, field: string, rowNumber: number, optional: boolean): VersionTuple | null {
  if (optional && value === null) {
    return null;
  }
  if (!Array.isArray(value) || value.length !== 3 || !value.every(isVersionComponent)) {
    throw new CatalogValidationError(`session row ${rowNumber} has an invalid ${field}`);
  }
  return [value[0], value[1], value[2]];
}

function isVersionComponent(value: unknown): value is number {
  return Number.isInteger(value) && typeof value === "number" && value >= 0 && value <= 65_535;
}

function parsePublishedAt(value: unknown, rowNumber: number): string | null {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== "string" || !Number.isFinite(Date.parse(value))) {
    throw new CatalogValidationError(`session row ${rowNumber} has an invalid publishedAt`);
  }
  return value;
}

export function versionSummary(version: VersionTuple | null): string {
  return version === null ? "unknown" : version.join(".");
}

export function lastPublishSummary(publishedAt: string | null, nowMilliseconds = Date.now()): string {
  if (publishedAt === null) {
    return "unknown";
  }

  const publishedMilliseconds = Date.parse(publishedAt);
  if (publishedMilliseconds - nowMilliseconds > 30_000) {
    return "clock skew";
  }

  const ageSeconds = Math.max(0, Math.floor((nowMilliseconds - publishedMilliseconds) / 1_000));
  if (ageSeconds < 60) {
    return `${ageSeconds}s ago`;
  }
  if (ageSeconds < 3_600) {
    return `${Math.floor(ageSeconds / 60)}m ago`;
  }
  if (ageSeconds < 86_400) {
    return `${Math.floor(ageSeconds / 3_600)}h ago`;
  }
  return `${Math.floor(ageSeconds / 86_400)}d ago`;
}

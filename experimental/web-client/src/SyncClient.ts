import type { IrohConnectionTarget } from "./IrohTransport";

const MAX_SYNC_BODY_BYTES = 98_304;
const REQUEST_TIMEOUT_MS = 10_000;

interface BrowserConnectionTargetBinding {
  readonly endpoint_ticket: string;
  readonly session: string;
  take_capability(): Uint8Array;
  take_consumer_identity(): Uint8Array;
  free(): void;
}

interface BrowserSyncClientBinding {
  readonly service_origin: string;
  readonly account_id: string;
  bearer_value(): string;
  begin_refresh(indexJson: Uint8Array): string;
  accept_record(
    recordId: string,
    etag: string,
    envelopeJson: Uint8Array,
    nowSeconds: number,
  ): void;
  finish_refresh(nowSeconds: number): string;
  abort_refresh(): void;
  sessions(nowSeconds: number): string;
  connection_for(
    recordId: string,
    session: string,
    nowSeconds: number,
  ): BrowserConnectionTargetBinding;
  free(): void;
}

interface BrowserSyncModule {
  default(): Promise<unknown>;
  BrowserSyncClient: new (accountBundle: string) => BrowserSyncClientBinding;
}

export type BrowserSyncLoader = () => Promise<BrowserSyncModule>;
export type SyncFetch = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;

const loadBrowserSync: BrowserSyncLoader = async () => {
  const generatedModule = "./sync-bindings/attached_browser_sync.js";
  return (await import(/* @vite-ignore */ generatedModule)) as BrowserSyncModule;
};

interface RefreshRecord {
  record_id: string;
  revision: string;
}

export interface SyncedSession {
  record_id: string;
  host_id: string;
  host_label: string;
  session: string;
  herdr_version: [number, number, number];
  expires_at: string;
}

export interface SyncRefreshResult {
  sessions: SyncedSession[];
  warnings: string[];
}

export class SyncClient {
  private closed = false;

  private constructor(
    private readonly binding: BrowserSyncClientBinding,
    private readonly fetcher: SyncFetch,
    private readonly now: () => number,
  ) {}

  static async fromBundle(
    accountBundle: string,
    loader: BrowserSyncLoader = loadBrowserSync,
    fetcher: SyncFetch = globalThis.fetch.bind(globalThis),
    now: () => number = () => Math.floor(Date.now() / 1_000),
  ): Promise<SyncClient> {
    const module = await loader();
    await module.default();
    let binding: BrowserSyncClientBinding;
    try {
      binding = new module.BrowserSyncClient(accountBundle);
    } catch {
      throw new Error("invalid account bundle");
    }
    return new SyncClient(binding, fetcher, now);
  }

  get serviceOrigin(): string {
    return this.binding.service_origin;
  }

  async refresh(signal?: AbortSignal): Promise<SyncRefreshResult> {
    this.ensureOpen();
    let refreshStarted = false;
    try {
      const authorization = this.binding.bearer_value();
      const indexBody = await fetchWithDeadline(
        this.fetcher,
        `${this.binding.service_origin}/v1/accounts/${this.binding.account_id}/records`,
        authorization,
        signal,
        async (response, requestSignal) => {
          ensureSuccessfulIndex(response);
          return readBoundedBody(response, requestSignal);
        },
      );
      const plan = parseRefreshPlan(this.binding.begin_refresh(indexBody));
      refreshStarted = true;
      const warnings: string[] = [];

      for (const record of plan.records) {
        throwIfAborted(signal);
        try {
          const downloaded = await fetchWithDeadline(
            this.fetcher,
            `${this.binding.service_origin}/v1/accounts/${this.binding.account_id}/records/${record.record_id}`,
            authorization,
            signal,
            async (response, requestSignal) => {
              if (response.status !== 200) {
                throw new Error(`service returned HTTP ${response.status}`);
              }
              ensureJson(response);
              const etag = response.headers.get("etag");
              if (etag === null) throw new Error("service response is missing ETag");
              return { etag, body: await readBoundedBody(response, requestSignal) };
            },
          );
          this.binding.accept_record(
            record.record_id,
            downloaded.etag,
            downloaded.body,
            this.nowSeconds(),
          );
        } catch (error) {
          if (isAbort(error, signal)) throw error;
          warnings.push(
            `Could not update synchronized record ${record.record_id}: ${safeMessage(error)}`,
          );
        }
      }

      const sessions = parseSessions(
        this.binding.finish_refresh(this.nowSeconds()),
      );
      refreshStarted = false;
      return { sessions, warnings };
    } catch (error) {
      if (refreshStarted) this.binding.abort_refresh();
      if (isAbort(error, signal)) throw error;
      return {
        sessions: this.cachedSessions(),
        warnings: [safeRefreshMessage(error)],
      };
    }
  }

  connectionFor(
    session: Pick<SyncedSession, "record_id" | "session">,
  ): IrohConnectionTarget {
    this.ensureOpen();
    const target = this.binding.connection_for(
      session.record_id,
      session.session,
      this.nowSeconds(),
    );
    try {
      const endpointTicket = target.endpoint_ticket;
      const sessionName = target.session;
      const capability = target.take_capability();
      let consumerIdentitySecret: Uint8Array;
      try {
        consumerIdentitySecret = target.take_consumer_identity();
      } catch (error) {
        capability.fill(0);
        throw error;
      }
      if (
        endpointTicket.length === 0 ||
        sessionName.length === 0 ||
        capability.length !== 32 ||
        consumerIdentitySecret.length !== 32
      ) {
        capability.fill(0);
        consumerIdentitySecret.fill(0);
        throw new Error("invalid synchronized connection target");
      }
      return {
        endpointTicket,
        session: sessionName,
        capability,
        consumerIdentitySecret,
      };
    } finally {
      target.free();
    }
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.binding.free();
  }

  private cachedSessions(): SyncedSession[] {
    try {
      return parseSessions(this.binding.sessions(this.nowSeconds()));
    } catch {
      return [];
    }
  }

  private nowSeconds(): number {
    const value = this.now();
    if (!Number.isSafeInteger(value) || value < 0) {
      throw new Error("invalid browser clock");
    }
    return value;
  }

  private ensureOpen(): void {
    if (this.closed) throw new Error("synchronization client is closed");
  }
}

function parseRefreshPlan(encoded: string): { records: RefreshRecord[] } {
  let value: unknown;
  try {
    value = JSON.parse(encoded);
  } catch {
    throw new Error("invalid synchronization refresh plan");
  }
  if (!isObject(value) || !Array.isArray(value.records)) {
    throw new Error("invalid synchronization refresh plan");
  }
  const records = value.records.map((record) => {
    if (
      !isObject(record) ||
      !isIdentifier(record.record_id) ||
      typeof record.revision !== "string" ||
      !/^[1-9][0-9]*$/.test(record.revision)
    ) {
      throw new Error("invalid synchronization refresh plan");
    }
    return { record_id: record.record_id, revision: record.revision };
  });
  return { records };
}

function parseSessions(encoded: string): SyncedSession[] {
  let value: unknown;
  try {
    value = JSON.parse(encoded);
  } catch {
    throw new Error("invalid synchronized session catalog");
  }
  if (!Array.isArray(value)) {
    throw new Error("invalid synchronized session catalog");
  }
  return value.map((session) => {
    if (
      !isObject(session) ||
      !isIdentifier(session.record_id) ||
      typeof session.host_id !== "string" ||
      session.host_id.length === 0 ||
      typeof session.host_label !== "string" ||
      session.host_label.length === 0 ||
      typeof session.session !== "string" ||
      session.session.length === 0 ||
      !Array.isArray(session.herdr_version) ||
      session.herdr_version.length !== 3 ||
      !session.herdr_version.every(
        (part) => Number.isInteger(part) && part >= 0 && part <= 65_535,
      ) ||
      typeof session.expires_at !== "string" ||
      !/^[1-9][0-9]*$/.test(session.expires_at)
    ) {
      throw new Error("invalid synchronized session catalog");
    }
    return {
      record_id: session.record_id,
      host_id: session.host_id,
      host_label: session.host_label,
      session: session.session,
      herdr_version: session.herdr_version as [number, number, number],
      expires_at: session.expires_at,
    };
  });
}

async function fetchWithDeadline<T>(
  fetcher: SyncFetch,
  url: string,
  authorization: string,
  signal: AbortSignal | undefined,
  consume: (response: Response, signal: AbortSignal) => Promise<T>,
): Promise<T> {
  throwIfAborted(signal);
  const controller = new AbortController();
  const abort = () => controller.abort(signal?.reason);
  signal?.addEventListener("abort", abort, { once: true });
  let timedOut = false;
  let responseReceived = false;
  const timeout = globalThis.setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, REQUEST_TIMEOUT_MS);
  try {
    const response = await fetcher(url, {
      method: "GET",
      cache: "no-store",
      credentials: "same-origin",
      redirect: "error",
      referrerPolicy: "no-referrer",
      headers: { Authorization: authorization },
      signal: controller.signal,
    });
    responseReceived = true;
    return await consume(response, controller.signal);
  } catch (error) {
    if (signal?.aborted === true) throw signal.reason ?? error;
    if (timedOut) {
      throw new Error("synchronization service request timed out");
    }
    if (responseReceived) throw error;
    throw new Error("unable to reach synchronization service");
  } finally {
    globalThis.clearTimeout(timeout);
    signal?.removeEventListener("abort", abort);
  }
}

function ensureSuccessfulIndex(response: Response): void {
  if (response.status === 401) {
    throw new Error("synchronization service rejected the account bundle");
  }
  if (response.status !== 200) {
    throw new Error(`synchronization service returned HTTP ${response.status}`);
  }
  ensureJson(response);
}

function ensureJson(response: Response): void {
  if (response.headers.get("content-type") !== "application/json") {
    throw new Error("synchronization service returned an unexpected content type");
  }
}

async function readBoundedBody(
  response: Response,
  signal?: AbortSignal,
): Promise<Uint8Array> {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null) {
    if (!/^(0|[1-9][0-9]*)$/.test(declaredLength)) {
      throw new Error("synchronization response has an invalid content length");
    }
    if (Number(declaredLength) > MAX_SYNC_BODY_BYTES) {
      throw new Error("synchronization response exceeds the browser limit");
    }
  }

  if (response.body === null) return new Uint8Array();
  const reader = response.body.getReader();
  const cancel = () => {
    void reader.cancel(signal?.reason).catch(() => undefined);
  };
  signal?.addEventListener("abort", cancel, { once: true });
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      throwIfAborted(signal);
      const next = await reader.read();
      throwIfAborted(signal);
      if (next.done) break;
      length += next.value.length;
      if (length > MAX_SYNC_BODY_BYTES) {
        await reader.cancel();
        throw new Error("synchronization response exceeds the browser limit");
      }
      chunks.push(next.value);
    }
  } finally {
    signal?.removeEventListener("abort", cancel);
    reader.releaseLock();
  }

  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.length;
  }
  return body;
}

function safeRefreshMessage(error: unknown): string {
  const message = safeMessage(error);
  return message.startsWith("synchronization") || message.startsWith("unable")
    ? message[0]!.toUpperCase() + message.slice(1)
    : `Could not refresh synchronized sessions: ${message}`;
}

function safeMessage(error: unknown): string {
  return error instanceof Error && error.message.length > 0
    ? error.message
    : "unexpected synchronization error";
}

function throwIfAborted(signal?: AbortSignal): void {
  if (signal?.aborted === true) {
    throw signal.reason ?? new DOMException("Aborted", "AbortError");
  }
}

function isAbort(error: unknown, signal?: AbortSignal): boolean {
  return (
    signal?.aborted === true ||
    (error instanceof DOMException && error.name === "AbortError")
  );
}

function isIdentifier(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_-]{22}$/.test(value);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

import { describe, expect, it, vi } from "vitest";
import {
  SyncClient,
  type BrowserSyncLoader,
  type SyncFetch,
} from "./SyncClient";

const recordId = "AAAAAAAAAAAAAAAAAAAAAA";
const session = {
  record_id: recordId,
  host_id: "hostidentity",
  host_label: "office",
  session: "alpha",
  herdr_version: [0, 7, 5] as [number, number, number],
  expires_at: "1700000300",
};

function fakeModule(
  options: { rejectRecord?: boolean; rejectConsumerIdentity?: boolean } = {},
) {
  const constructor = vi.fn();
  const free = vi.fn();
  const beginRefresh = vi.fn(() =>
    JSON.stringify({ records: [{ record_id: recordId, revision: "3" }] }),
  );
  const acceptRecord = options.rejectRecord
    ? vi.fn(() => {
        throw new Error("manifest rejected: decryption failed");
      })
    : vi.fn();
  const finishRefresh = vi.fn(() => JSON.stringify([session]));
  const abortRefresh = vi.fn();
  const sessions = vi.fn(() => JSON.stringify([session]));
  const freeTarget = vi.fn();
  const capability = new Uint8Array(32).fill(7);
  const takeCapability = vi.fn(() => capability);
  const takeConsumerIdentity = options.rejectConsumerIdentity
    ? vi.fn(() => {
        throw new Error("consumer identity extraction failed");
      })
    : vi.fn(() => new Uint8Array(32).fill(8));
  const connectionFor = vi.fn(() => ({
    endpoint_ticket: "endpoint-ticket",
    session: "alpha",
    take_capability: takeCapability,
    take_consumer_identity: takeConsumerIdentity,
    free: freeTarget,
  }));

  class BrowserSyncClient {
    readonly service_origin = "https://sync.example";
    readonly account_id = "BBBBBBBBBBBBBBBBBBBBBB";

    constructor(bundle: string) {
      constructor(bundle);
    }

    bearer_value = vi.fn(() => "Bearer synthetic-token");
    begin_refresh = beginRefresh;
    accept_record = acceptRecord;
    finish_refresh = finishRefresh;
    abort_refresh = abortRefresh;
    sessions = sessions;
    connection_for = connectionFor;
    free = free;
  }

  const initialize = vi.fn(async () => undefined);
  const loader = vi.fn(async () => ({
    default: initialize,
    BrowserSyncClient,
  })) as BrowserSyncLoader;
  return {
    loader,
    initialize,
    constructor,
    free,
    beginRefresh,
    acceptRecord,
    finishRefresh,
    abortRefresh,
    sessions,
    connectionFor,
    capability,
    takeCapability,
    takeConsumerIdentity,
    freeTarget,
  };
}

function jsonResponse(body: string, init: ResponseInit = {}): Response {
  const headers = new Headers(init.headers);
  headers.set("content-type", "application/json");
  return new Response(body, { ...init, headers, status: init.status ?? 200 });
}

describe("browser synchronization client", () => {
  it("downloads the complete index, opens changed records, and returns sessions", async () => {
    const wasm = fakeModule();
    const fetcher = vi
      .fn<SyncFetch>()
      .mockResolvedValueOnce(jsonResponse('{"records":[]}'))
      .mockResolvedValueOnce(
        jsonResponse('{"envelope_version":1}', {
          headers: { etag: '"3"' },
        }),
      );
    const client = await SyncClient.fromBundle(
      "synthetic-bundle",
      wasm.loader,
      fetcher,
      () => 1_700_000_100,
    );

    await expect(client.refresh()).resolves.toEqual({ sessions: [session], warnings: [] });

    expect(wasm.initialize).toHaveBeenCalledOnce();
    expect(wasm.constructor).toHaveBeenCalledWith("synthetic-bundle");
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls[0]?.[0]).toBe(
      "https://sync.example/v1/accounts/BBBBBBBBBBBBBBBBBBBBBB/records",
    );
    expect(fetcher.mock.calls[1]?.[0]).toBe(
      `https://sync.example/v1/accounts/BBBBBBBBBBBBBBBBBBBBBB/records/${recordId}`,
    );
    expect(fetcher.mock.calls[0]?.[1]).toMatchObject({
      method: "GET",
      credentials: "same-origin",
      redirect: "error",
      headers: { Authorization: "Bearer synthetic-token" },
    });
    expect(wasm.acceptRecord).toHaveBeenCalledWith(
      recordId,
      '"3"',
      expect.any(Uint8Array),
      1_700_000_100,
    );
    expect(wasm.finishRefresh).toHaveBeenCalledWith(1_700_000_100);

    expect(client.connectionFor(session)).toEqual({
      endpointTicket: "endpoint-ticket",
      session: "alpha",
      capability: new Uint8Array(32).fill(7),
      consumerIdentitySecret: new Uint8Array(32).fill(8),
    });
    expect(wasm.connectionFor).toHaveBeenCalledWith(recordId, "alpha", 1_700_000_100);
    expect(wasm.takeCapability).toHaveBeenCalledOnce();
    expect(wasm.takeConsumerIdentity).toHaveBeenCalledOnce();
    expect(wasm.freeTarget).toHaveBeenCalledOnce();
    client.close();
    client.close();
    expect(wasm.free).toHaveBeenCalledOnce();
  });

  it("zeroizes an extracted capability when consumer identity extraction fails", async () => {
    const wasm = fakeModule({ rejectConsumerIdentity: true });
    const client = await SyncClient.fromBundle("bundle", wasm.loader);

    expect(() => client.connectionFor(session)).toThrow(
      "consumer identity extraction failed",
    );

    expect(wasm.takeCapability).toHaveBeenCalledOnce();
    expect(wasm.takeConsumerIdentity).toHaveBeenCalledOnce();
    expect(wasm.capability).toEqual(new Uint8Array(32));
    expect(wasm.freeTarget).toHaveBeenCalledOnce();
  });

  it("keeps refreshing healthy records when one encrypted record is rejected", async () => {
    const wasm = fakeModule({ rejectRecord: true });
    const fetcher = vi
      .fn<SyncFetch>()
      .mockResolvedValueOnce(jsonResponse("{}"))
      .mockResolvedValueOnce(jsonResponse("{}", { headers: { etag: '"3"' } }));
    const client = await SyncClient.fromBundle("bundle", wasm.loader, fetcher);

    const result = await client.refresh();

    expect(result.sessions).toEqual([session]);
    expect(result.warnings).toEqual([
      `Could not update synchronized record ${recordId}: manifest rejected: decryption failed`,
    ]);
    expect(wasm.finishRefresh).toHaveBeenCalledOnce();
    expect(wasm.abortRefresh).not.toHaveBeenCalled();
  });

  it("returns the cached catalog when the service cannot be reached", async () => {
    const wasm = fakeModule();
    const fetcher = vi.fn<SyncFetch>().mockRejectedValue(new Error("secret URL details"));
    const client = await SyncClient.fromBundle("bundle", wasm.loader, fetcher);

    await expect(client.refresh()).resolves.toEqual({
      sessions: [session],
      warnings: ["Unable to reach synchronization service"],
    });
    expect(wasm.sessions).toHaveBeenCalledOnce();
    expect(wasm.beginRefresh).not.toHaveBeenCalled();
  });

  it("keeps the request deadline active while streaming the response body", async () => {
    vi.useFakeTimers();
    try {
      const wasm = fakeModule();
      const cancel = vi.fn();
      const pull = vi.fn(() => new Promise<void>(() => undefined));
      const body = new ReadableStream<Uint8Array>({ pull, cancel });
      const fetcher = vi.fn<SyncFetch>().mockResolvedValue(
        new Response(body, {
          headers: { "content-type": "application/json" },
          status: 200,
        }),
      );
      const client = await SyncClient.fromBundle("bundle", wasm.loader, fetcher);

      const refresh = client.refresh();
      await vi.waitFor(() => expect(pull).toHaveBeenCalledOnce());
      await vi.advanceTimersByTimeAsync(10_000);

      expect(cancel).toHaveBeenCalledOnce();
      await expect(refresh).resolves.toEqual({
        sessions: [session],
        warnings: ["Synchronization service request timed out"],
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("propagates caller abort while streaming the response body", async () => {
    const wasm = fakeModule();
    const cancel = vi.fn();
    const pull = vi.fn(() => new Promise<void>(() => undefined));
    const body = new ReadableStream<Uint8Array>({ pull, cancel });
    const fetcher = vi.fn<SyncFetch>().mockResolvedValue(
      new Response(body, {
        headers: { "content-type": "application/json" },
        status: 200,
      }),
    );
    const client = await SyncClient.fromBundle("bundle", wasm.loader, fetcher);
    const controller = new AbortController();

    const refresh = client.refresh(controller.signal);
    const outcome = refresh.catch((error: unknown) => error);
    await vi.waitFor(() => expect(pull).toHaveBeenCalledOnce());
    controller.abort(new DOMException("stop refresh", "AbortError"));

    expect(cancel).toHaveBeenCalledOnce();
    await expect(outcome).resolves.toMatchObject({
      name: "AbortError",
      message: "stop refresh",
    });
  });

  it("redacts malformed bundle details from WASM constructor failures", async () => {
    class BrowserSyncClient {
      constructor(bundle: string) {
        throw new Error(`invalid secret ${bundle}`);
      }
    }
    const loader = vi.fn(async () => ({
      default: vi.fn(async () => undefined),
      BrowserSyncClient,
    })) as unknown as BrowserSyncLoader;

    await expect(
      SyncClient.fromBundle("private-account-bundle", loader),
    ).rejects.toThrow("invalid account bundle");
    await expect(
      SyncClient.fromBundle("private-account-bundle", loader),
    ).rejects.not.toThrow("private-account-bundle");
  });
});

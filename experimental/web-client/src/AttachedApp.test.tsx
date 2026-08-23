import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => {
  const send = vi.fn(async () => undefined);
  const receive = vi
    .fn<() => Promise<Uint8Array | undefined>>()
    .mockResolvedValueOnce(new Uint8Array([9]))
    .mockResolvedValueOnce(undefined);
  const close = vi.fn(async () => undefined);
  const write = vi.fn();
  const focus = vi.fn();
  const connect = vi.fn(async () => ({ send, receive, close }));
  const encodeHello = vi.fn(() => new Uint8Array([1]));
  const encodeInput = vi.fn((data: string) => new Uint8Array([data.length]));
  const pushServerBytes = vi.fn(() => [
    { type: "control", message: { type: "ready", protocol: 17 } },
  ]);
  const syncedSession = {
    record_id: "AAAAAAAAAAAAAAAAAAAAAA",
    host_id: "hostidentity",
    host_label: "office",
    session: "alpha",
    herdr_version: [0, 7, 5] as [number, number, number],
    expires_at: "1700000300",
  };
  const connectionTarget = {
    endpointTicket: "endpoint-ticket",
    session: "alpha",
    capability: new Uint8Array(32).fill(7),
  };
  const refreshSync = vi.fn(async () => ({ sessions: [syncedSession], warnings: [] }));
  const connectionFor = vi.fn(() => connectionTarget);
  const closeSync = vi.fn();
  const syncClient = {
    refresh: refreshSync,
    connectionFor,
    close: closeSync,
  };
  const fromBundle = vi.fn(async () => syncClient);
  return {
    send,
    receive,
    close,
    write,
    focus,
    connect,
    encodeHello,
    encodeInput,
    pushServerBytes,
    syncedSession,
    connectionTarget,
    refreshSync,
    connectionFor,
    closeSync,
    syncClient,
    fromBundle,
  };
});

vi.mock("@wterm/react", () => ({
  useTerminal: () => ({
    ref: { current: null },
    write: mocks.write,
    focus: mocks.focus,
  }),
  Terminal: () => <div aria-label="Real Herdr terminal" />,
}));

vi.mock("./IrohTransport", async (importOriginal) => {
  const original = await importOriginal<typeof import("./IrohTransport")>();
  return {
    ...original,
    IrohTransport: { connect: mocks.connect },
  };
});

vi.mock("./HerdrTuiProtocol", () => ({
  HerdrTuiProtocol: {
    load: vi.fn(async () => ({
      encodeHello: mocks.encodeHello,
      encodeResize: vi.fn(() => new Uint8Array([2])),
      encodeInput: mocks.encodeInput,
      encodeDetach: vi.fn(() => new Uint8Array([4])),
      pushServerBytes: mocks.pushServerBytes,
    })),
  },
}));

vi.mock("./SyncClient", () => ({
  SyncClient: { fromBundle: mocks.fromBundle },
}));

import { AttachedApp } from "./AttachedApp";

let userAgent = "Mozilla/5.0 (X11; Linux x86_64) Chrome/124 Safari/537.36";

async function openSession() {
  render(<AttachedApp />);
  fireEvent.change(screen.getByLabelText("Account bundle"), {
    target: { value: "attached-account-v2:synthetic" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Load sessions" }));
  fireEvent.click(await screen.findByRole("button", { name: /alpha/ }));
}

describe("Attached Iroh app", () => {
  beforeEach(() => {
    vi.spyOn(window.navigator, "userAgent", "get").mockImplementation(() => userAgent);
    userAgent = "Mozilla/5.0 (X11; Linux x86_64) Chrome/124 Safari/537.36";
    vi.clearAllMocks();
    mocks.connect.mockImplementation(async () => ({
      send: mocks.send,
      receive: mocks.receive,
      close: mocks.close,
    }));
    mocks.receive
      .mockResolvedValueOnce(new Uint8Array([9]))
      .mockResolvedValueOnce(undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("starts with account-bundle onboarding", () => {
    render(<AttachedApp />);

    expect(screen.getByRole("heading", { name: "Connect to your Herdr sessions" })).toBeVisible();
    expect(screen.getByLabelText("Account bundle")).toHaveAttribute("type", "password");
    expect(screen.getByText(/never saved in browser storage/)).toBeVisible();
    expect(mocks.connect).not.toHaveBeenCalled();
  });

  it("refreshes initially and whenever the user returns from a TUI", async () => {
    await openSession();

    expect(mocks.fromBundle).toHaveBeenCalledWith("attached-account-v2:synthetic");
    expect(mocks.refreshSync).toHaveBeenCalledOnce();
    expect(mocks.connectionFor).toHaveBeenCalledWith({
      record_id: mocks.syncedSession.record_id,
      session: mocks.syncedSession.session,
    });
    await waitFor(() =>
      expect(mocks.connect).toHaveBeenCalledWith(
        mocks.connectionTarget,
        undefined,
        expect.any(AbortSignal),
      ),
    );

    const backToSessions = screen.getByRole("button", { name: "Back to sessions" });
    expect(backToSessions).toHaveTextContent("← Sessions");
    fireEvent.click(backToSessions);

    expect(await screen.findByRole("button", { name: /alpha/ })).toBeVisible();
    await waitFor(() => expect(mocks.refreshSync).toHaveBeenCalledTimes(2));
  });

  it("groups synchronized sessions under host dividers", async () => {
    mocks.refreshSync.mockResolvedValueOnce({
      sessions: [
        mocks.syncedSession,
        { ...mocks.syncedSession, session: "beta" },
        {
          ...mocks.syncedSession,
          record_id: "BBBBBBBBBBBBBBBBBBBBBB",
          host_id: "homehostidentity",
          host_label: "home",
          session: "gamma",
        },
      ],
      warnings: [],
    });
    render(<AttachedApp />);

    fireEvent.change(screen.getByLabelText("Account bundle"), {
      target: { value: "attached-account-v2:synthetic" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Load sessions" }));

    await screen.findByRole("button", { name: /gamma/ });
    expect(
      screen.getAllByRole("heading", { level: 2 }).map((heading) => heading.textContent),
    ).toEqual(["home", "office"]);

    const home = screen.getByRole("region", { name: "Sessions on home" });
    const office = screen.getByRole("region", { name: "Sessions on office" });
    expect(within(home).getByText("homehost · 1 session")).toBeVisible();
    expect(within(home).getAllByRole("button")).toHaveLength(1);
    expect(within(office).getByText("hostiden · 2 sessions")).toBeVisible();
    expect(within(office).getAllByRole("button")).toHaveLength(2);
  });

  it("shows the primary action bar only for phone user agents", async () => {
    userAgent =
      "Mozilla/5.0 (iPhone; CPU iPhone OS 18_5 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1";

    await openSession();

    expect(screen.getByRole("navigation", { name: "Herdr mobile actions" })).toBeVisible();
    expect(screen.getByRole("button", { name: "New pane" })).toBeVisible();
    expect(screen.getByRole("button", { name: "New tab" })).toBeVisible();
    expect(screen.getByRole("button", { name: "New workspace" })).toBeVisible();
  });

  it("sends the default Herdr action bindings from phone buttons", async () => {
    userAgent =
      "Mozilla/5.0 (Linux; Android 16; Pixel 10) AppleWebKit/537.36 Chrome/140 Mobile Safari/537.36";
    mocks.receive
      .mockReset()
      .mockResolvedValueOnce(new Uint8Array([9]))
      .mockImplementationOnce(() => new Promise(() => undefined));

    await openSession();

    const newPane = screen.getByRole("button", { name: "New pane" });
    const newTab = screen.getByRole("button", { name: "New tab" });
    const newWorkspace = screen.getByRole("button", { name: "New workspace" });
    await waitFor(() => expect(newPane).toBeEnabled());

    fireEvent.click(newPane);
    fireEvent.click(newTab);
    fireEvent.click(newWorkspace);

    expect(mocks.encodeInput.mock.calls.map(([data]) => data)).toEqual([
      "\u0002v",
      "\u0002c",
      "\u0002N",
    ]);
  });

  it("authenticates over Iroh and closes transport resources after EOF", async () => {
    await openSession();

    await waitFor(() =>
      expect(mocks.connect).toHaveBeenCalledWith(
        mocks.connectionTarget,
        undefined,
        expect.any(AbortSignal),
      ),
    );
    expect(mocks.encodeHello).toHaveBeenCalled();
    expect(mocks.send).toHaveBeenCalledWith(new Uint8Array([1]));
    expect(mocks.pushServerBytes).toHaveBeenCalledWith(new Uint8Array([9]));
    await waitFor(() => expect(mocks.close).toHaveBeenCalledOnce());
  });

  it("closes after the bounded detach attempt stalls", async () => {
    mocks.receive.mockImplementation(() => new Promise(() => undefined));
    mocks.send
      .mockResolvedValueOnce(undefined)
      .mockImplementationOnce(() => new Promise(() => undefined));
    render(<AttachedApp />);
    fireEvent.change(screen.getByLabelText("Account bundle"), {
      target: { value: "attached-account-v2:synthetic" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Load sessions" }));
    fireEvent.click(await screen.findByRole("button", { name: /alpha/ }));
    await waitFor(() => expect(mocks.send).toHaveBeenCalledWith(new Uint8Array([1])));

    fireEvent.click(screen.getByRole("button", { name: "Back to sessions" }));

    await waitFor(() => expect(mocks.close).toHaveBeenCalledOnce(), { timeout: 1_000 });
  });
});

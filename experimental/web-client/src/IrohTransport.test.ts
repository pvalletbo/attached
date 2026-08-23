import { describe, expect, it, vi } from "vitest";
import { IrohTransport, type IrohConnectionTarget } from "./IrohTransport";

function target(): IrohConnectionTarget {
  return {
    endpointTicket: "endpoint-ticket",
    session: "alpha",
    capability: new Uint8Array(32).fill(7),
  };
}

function fakeBinding() {
  const tunnel = {
    send: vi.fn(async () => undefined),
    receive: vi.fn(async () => new Uint8Array([4, 2])),
    close: vi.fn<() => Promise<void>>(async () => undefined),
  };
  const initialize = vi.fn(async () => undefined);
  const receivedCapabilities: Uint8Array[] = [];
  const connect = vi.fn(
    async (_endpoint: string, _session: string, capability: Uint8Array) => {
      receivedCapabilities.push(capability.slice());
      return tunnel;
    },
  );
  const cancel = vi.fn();
  const free = vi.fn();
  class BrowserConnector {
    connect = connect;
    cancel = cancel;
    free = free;
  }
  return {
    tunnel,
    initialize,
    connect,
    receivedCapabilities,
    cancel,
    free,
    load: vi.fn(async () => ({
      default: initialize,
      BrowserConnector,
    })),
  };
}

describe("browser Iroh transport", () => {
  it("initializes WASM and forwards opaque bytes", async () => {
    const binding = fakeBinding();
    const connection = target();
    const transport = await IrohTransport.connect(connection, binding.load);
    const outgoing = new Uint8Array([1, 2, 3]);

    await transport.send(outgoing);
    await expect(transport.receive()).resolves.toEqual(new Uint8Array([4, 2]));
    await transport.close();

    expect(binding.initialize).toHaveBeenCalledOnce();
    expect(binding.connect).toHaveBeenCalledWith(
      "endpoint-ticket",
      "alpha",
      expect.any(Uint8Array),
    );
    expect(binding.receivedCapabilities).toEqual([new Uint8Array(32).fill(7)]);
    expect(connection.capability).toEqual(new Uint8Array(32));
    expect(binding.tunnel.send).toHaveBeenCalledWith(outgoing);
    expect(binding.tunnel.close).toHaveBeenCalledOnce();
  });

  it("does not expose connection credentials in errors", async () => {
    const secret = new Uint8Array(32).fill(9);
    const load = vi.fn(async () => ({
      default: vi.fn(async () => undefined),
      BrowserConnector: class {
        connect = vi.fn(async () => {
          throw new Error(`bad capability ${String(secret[0])}`);
        });
        cancel = vi.fn();
        free = vi.fn();
      },
    }));

    await expect(
      IrohTransport.connect(
        { endpointTicket: "private-endpoint", session: "alpha", capability: secret },
        load,
      ),
    ).rejects.toThrow("unable to connect to the Herdr tunnel");
    expect(secret).toEqual(new Uint8Array(32));
  });

  it("closes only once", async () => {
    const binding = fakeBinding();
    const transport = await IrohTransport.connect(target(), binding.load);

    await Promise.all([transport.close(), transport.close()]);

    expect(binding.tunnel.close).toHaveBeenCalledOnce();
  });

  it("makes concurrent close callers await the same shutdown", async () => {
    let release!: () => void;
    const binding = fakeBinding();
    binding.tunnel.close.mockImplementationOnce(
      () => new Promise<void>((resolve) => (release = resolve)),
    );
    const transport = await IrohTransport.connect(target(), binding.load);

    const first = transport.close();
    const second = transport.close();
    let secondFinished = false;
    void second.then(() => (secondFinished = true));
    await Promise.resolve();

    expect(secondFinished).toBe(false);
    expect(first).toBe(second);
    release();
    await Promise.all([first, second]);
  });

  it("cancels a pending WASM connection when aborted", async () => {
    const binding = fakeBinding();
    binding.connect.mockImplementationOnce(() => new Promise(() => undefined));
    const controller = new AbortController();

    void IrohTransport.connect(target(), binding.load, controller.signal);
    await vi.waitFor(() => expect(binding.connect).toHaveBeenCalledOnce());
    controller.abort();

    expect(binding.cancel).toHaveBeenCalledOnce();
  });
});

interface BrowserTunnelBinding {
  send(bytes: Uint8Array): Promise<void>;
  receive(): Promise<Uint8Array | undefined>;
  close(): Promise<void>;
}

interface BrowserIrohModule {
  default(): Promise<unknown>;
  BrowserConnector: new () => {
    connect(
      endpointTicket: string,
      session: string,
      capability: Uint8Array,
    ): Promise<BrowserTunnelBinding>;
    cancel(): void;
    free(): void;
  };
}

export interface IrohConnectionTarget {
  endpointTicket: string;
  session: string;
  capability: Uint8Array;
}

export type BrowserIrohLoader = () => Promise<BrowserIrohModule>;

const loadBrowserIroh: BrowserIrohLoader = async () => {
  const generatedModule = "./iroh-bindings/attached_browser_iroh.js";
  return (await import(/* @vite-ignore */ generatedModule)) as BrowserIrohModule;
};

export class IrohTransport {
  private closePromise: Promise<void> | undefined;

  private constructor(private readonly tunnel: BrowserTunnelBinding) {}

  static async connect(
    target: IrohConnectionTarget,
    load: BrowserIrohLoader = loadBrowserIroh,
    signal?: AbortSignal,
  ): Promise<IrohTransport> {
    let connector:
      | InstanceType<(Awaited<ReturnType<BrowserIrohLoader>>)["BrowserConnector"]>
      | undefined;
    const cancel = () => connector?.cancel();
    try {
      const module = await load();
      await module.default();
      connector = new module.BrowserConnector();
      signal?.addEventListener("abort", cancel, { once: true });
      if (signal?.aborted === true) connector.cancel();
      const tunnel = await connector.connect(
        target.endpointTicket,
        target.session,
        target.capability,
      );
      return new IrohTransport(tunnel);
    } catch {
      throw new Error("unable to connect to the Herdr tunnel");
    } finally {
      target.capability.fill(0);
      signal?.removeEventListener("abort", cancel);
      connector?.free();
    }
  }

  async send(bytes: Uint8Array): Promise<void> {
    if (this.closePromise !== undefined) throw new Error("Herdr tunnel is closed");
    try {
      await this.tunnel.send(bytes);
    } catch {
      throw new Error("unable to send Herdr tunnel data");
    }
  }

  async receive(): Promise<Uint8Array | undefined> {
    if (this.closePromise !== undefined) return undefined;
    try {
      return await this.tunnel.receive();
    } catch {
      throw new Error("unable to receive Herdr tunnel data");
    }
  }

  close(): Promise<void> {
    this.closePromise ??= this.tunnel.close();
    return this.closePromise;
  }
}

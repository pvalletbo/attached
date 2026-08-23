const MAX_FRAME_SIZE = 32 * 1024 * 1024;
const INITIAL_PENDING_CAPACITY = 64 * 1024;
const MAX_PENDING_SIZE = MAX_FRAME_SIZE + 4 + INITIAL_PENDING_CAPACITY;
const DECODE_OUTPUT = 1;
const DECODE_CONTROL = 2;
const DECODE_ERROR = 3;

interface ProtocolDecodeResultBinding {
  readonly kind: number;
  take_bytes(): Uint8Array;
}

interface ProtocolModule {
  default(): Promise<unknown>;
  protocol_encode_hello(columns: number, rows: number): Uint8Array;
  protocol_encode_resize(columns: number, rows: number): Uint8Array;
  protocol_encode_input(input: Uint8Array): Uint8Array;
  protocol_encode_detach(): Uint8Array;
  protocol_decode_server(payload: Uint8Array): ProtocolDecodeResultBinding;
}

export type HerdrProtocolLoader = () => Promise<ProtocolModule>;

const loadProtocolModule: HerdrProtocolLoader = async () => {
  const generatedModule = "./protocol-bindings/herdr_tui_protocol.js";
  return (await import(/* @vite-ignore */ generatedModule)) as ProtocolModule;
};

export type HerdrProtocolEvent =
  | { type: "output"; data: Uint8Array }
  | { type: "control"; message: Record<string, unknown> };

export class HerdrTuiProtocol {
  private pending = new Uint8Array(INITIAL_PENDING_CAPACITY);
  private pendingLength = 0;

  private constructor(private readonly wasm: ProtocolModule) {}

  static async load(
    loader: HerdrProtocolLoader = loadProtocolModule,
  ): Promise<HerdrTuiProtocol> {
    const wasm = await loader();
    await wasm.default();
    return new HerdrTuiProtocol(wasm);
  }

  encodeHello(columns: number, rows: number): Uint8Array {
    return this.wasm.protocol_encode_hello(columns, rows);
  }

  encodeResize(columns: number, rows: number): Uint8Array {
    return this.wasm.protocol_encode_resize(columns, rows);
  }

  encodeInput(data: string): Uint8Array {
    return this.wasm.protocol_encode_input(new TextEncoder().encode(data));
  }

  encodeDetach(): Uint8Array {
    return this.wasm.protocol_encode_detach();
  }

  pushServerBytes(chunk: Uint8Array): HerdrProtocolEvent[] {
    const required = this.pendingLength + chunk.length;
    if (required > MAX_PENDING_SIZE) {
      throw new Error(`Herdr protocol pending data exceeds ${MAX_PENDING_SIZE} bytes`);
    }
    if (required > this.pending.length) {
      const capacity = Math.min(
        MAX_PENDING_SIZE,
        Math.max(required, this.pending.length * 2),
      );
      const grown = new Uint8Array(capacity);
      grown.set(this.pending.subarray(0, this.pendingLength));
      this.pending = grown;
    }
    this.pending.set(chunk, this.pendingLength);
    this.pendingLength = required;

    const events: HerdrProtocolEvent[] = [];
    let offset = 0;
    while (this.pendingLength - offset >= 4) {
      const view = new DataView(
        this.pending.buffer,
        this.pending.byteOffset + offset,
        this.pendingLength - offset,
      );
      const payloadLength = view.getUint32(0, true);
      if (payloadLength > MAX_FRAME_SIZE) {
        throw new Error(
          `Herdr protocol frame ${payloadLength} exceeds ${MAX_FRAME_SIZE} bytes`,
        );
      }
      if (this.pendingLength - offset - 4 < payloadLength) break;

      const payload = this.pending.subarray(offset + 4, offset + 4 + payloadLength);
      events.push(this.decodePayload(payload));
      offset += 4 + payloadLength;
    }

    if (offset > 0) {
      this.pending.copyWithin(0, offset, this.pendingLength);
      this.pendingLength -= offset;
    }
    return events;
  }

  private decodePayload(payload: Uint8Array): HerdrProtocolEvent {
    const decoded = this.wasm.protocol_decode_server(payload);
    const kind = decoded.kind;
    const result = decoded.take_bytes();

    if (kind === DECODE_OUTPUT) {
      return { type: "output", data: result };
    }

    const message = JSON.parse(new TextDecoder().decode(result)) as Record<
      string,
      unknown
    >;
    if (kind === DECODE_ERROR) {
      throw new Error(
        typeof message.error === "string" ? message.error : "Herdr protocol error",
      );
    }
    if (kind !== DECODE_CONTROL) {
      throw new Error(`unknown Herdr protocol decoder result ${kind}`);
    }
    return { type: "control", message };
  }
}

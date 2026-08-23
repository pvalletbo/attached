import { Terminal, useTerminal } from "@wterm/react";
import {
  useEffect,
  useRef,
  useState,
  type FormEvent,
  type KeyboardEvent as ReactKeyboardEvent,
  type MouseEvent as ReactMouseEvent,
} from "react";
import { HerdrTuiProtocol } from "./HerdrTuiProtocol";
import { IrohTransport } from "./IrohTransport";
import { DEFAULT_MOBILE_ACTIONS, isPhoneUserAgent } from "./mobileActions";
import { SyncClient, type SyncedSession } from "./SyncClient";
import { encodeCsiUKey } from "./terminalKeyboard";
import { encodeSgrMouseEvent, terminalCellFromPoint } from "./terminalMouse";

const DETACH_TIMEOUT_MS = 250;

export function AttachedApp() {
  const [syncClient, setSyncClient] = useState<SyncClient>();
  const [selectedSession, setSelectedSession] = useState<SyncedSession>();

  useEffect(() => () => syncClient?.close(), [syncClient]);

  if (syncClient === undefined) {
    return <AccountBundlePrompt onConnected={setSyncClient} />;
  }

  if (selectedSession !== undefined) {
    return (
      <HerdrTerminal
        syncClient={syncClient}
        syncedSession={selectedSession}
        onBack={() => setSelectedSession(undefined)}
      />
    );
  }

  return (
    <SessionCatalog
      client={syncClient}
      onSelect={setSelectedSession}
      onChangeAccount={() => setSyncClient(undefined)}
    />
  );
}

function AccountBundlePrompt({
  onConnected,
}: {
  onConnected(client: SyncClient): void;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string>();

  const submit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const form = event.currentTarget;
    const input = form.elements.namedItem("accountBundle");
    if (!(input instanceof HTMLInputElement)) return;
    const bundle = input.value.trim();
    input.value = "";
    if (bundle.length === 0) {
      setError("Enter an account bundle.");
      return;
    }

    setBusy(true);
    setError(undefined);
    void SyncClient.fromBundle(bundle)
      .then(onConnected)
      .catch(() => setError("The account bundle is invalid."))
      .finally(() => setBusy(false));
  };

  return (
    <main className="catalog-shell onboarding-shell">
      <section className="account-card" aria-labelledby="account-heading">
        <span className="eyebrow">Encrypted session synchronization</span>
        <h1 id="account-heading">Connect to your Herdr sessions</h1>
        <p>
          Paste the download bundle created by <code>attached</code>.
          It is parsed locally and is never saved in browser storage.
        </p>
        <form onSubmit={submit}>
          <label htmlFor="account-bundle">Account bundle</label>
          <input
            id="account-bundle"
            name="accountBundle"
            type="password"
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            placeholder="URL-safe base64 bundle…"
            disabled={busy}
            autoFocus
          />
          {error === undefined ? null : <div className="form-error" role="alert">{error}</div>}
          <button type="submit" className="primary-button" disabled={busy}>
            {busy ? "Opening bundle…" : "Load sessions"}
          </button>
        </form>
        <small>
          The bundle contains your account root key and API token. Only enter it
          on a trusted copy of this web client.
        </small>
      </section>
    </main>
  );
}

interface SessionHostGroup {
  hostId: string;
  hostLabel: string;
  sessions: SyncedSession[];
}

function groupSessionsByHost(sessions: SyncedSession[]): SessionHostGroup[] {
  const groups = new Map<string, SessionHostGroup>();
  for (const session of sessions) {
    const group = groups.get(session.host_id);
    if (group === undefined) {
      groups.set(session.host_id, {
        hostId: session.host_id,
        hostLabel: session.host_label,
        sessions: [session],
      });
    } else {
      group.sessions.push(session);
    }
  }

  return [...groups.values()]
    .map((group) => ({
      ...group,
      sessions: [...group.sessions].sort((left, right) =>
        left.session.localeCompare(right.session),
      ),
    }))
    .sort(
      (left, right) =>
        left.hostLabel.localeCompare(right.hostLabel) ||
        left.hostId.localeCompare(right.hostId),
    );
}

function SessionCatalog({
  client,
  onSelect,
  onChangeAccount,
}: {
  client: SyncClient;
  onSelect(session: SyncedSession): void;
  onChangeAccount(): void;
}) {
  const [sessions, setSessions] = useState<SyncedSession[]>([]);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [refreshing, setRefreshing] = useState(true);
  const [refreshAttempt, setRefreshAttempt] = useState(0);

  useEffect(() => {
    document.title = "Attached";
    const controller = new AbortController();
    void client
      .refresh(controller.signal)
      .then((result) => {
        if (controller.signal.aborted) return;
        setSessions(result.sessions);
        setWarnings(result.warnings);
      })
      .catch(() => {
        if (!controller.signal.aborted) {
          setWarnings(["Could not refresh synchronized sessions."]);
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setRefreshing(false);
      });
    return () => controller.abort();
  }, [client, refreshAttempt]);

  const hostGroups = groupSessionsByHost(sessions);

  return (
    <main className="catalog-shell">
      <header className="catalog-header">
        <div>
          <h1>Attached</h1>
          <span>{refreshing ? "Checking for new sessions…" : `${sessions.length} available`}</span>
        </div>
        <div className="catalog-actions">
          <button
            type="button"
            disabled={refreshing}
            onClick={() => {
              setRefreshing(true);
              setRefreshAttempt((attempt) => attempt + 1);
            }}
          >
            Refresh
          </button>
          <button type="button" onClick={onChangeAccount}>Change account</button>
        </div>
      </header>

      <section className="session-list" aria-label="Synchronized Herdr sessions" aria-busy={refreshing}>
        {warnings.map((warning) => (
          <div className="catalog-warning" role="alert" key={warning}>{warning}</div>
        ))}
        {hostGroups.map((group) => (
          <section
            className="host-session-group"
            aria-label={`Sessions on ${group.hostLabel}`}
            key={group.hostId}
          >
            <div className="host-divider">
              <h2>{group.hostLabel}</h2>
              <span>
                {group.hostId.slice(0, 8)} · {group.sessions.length}{" "}
                {group.sessions.length === 1 ? "session" : "sessions"}
              </span>
            </div>
            <div className="host-session-grid">
              {group.sessions.map((session) => {
                const version = session.herdr_version.join(".");
                return (
                  <button
                    className="session-card"
                    type="button"
                    key={`${session.record_id}/${session.session}`}
                    onClick={() => onSelect(session)}
                  >
                    <span className="session-name">{session.session}</span>
                    <span className="session-host">{session.host_label}</span>
                    <span className="session-version">Herdr {version}</span>
                    <span className="session-connect">Connect →</span>
                  </button>
                );
              })}
            </div>
          </section>
        ))}
        {!refreshing && sessions.length === 0 ? (
          <div className="empty-catalog">
            <strong>No active sessions</strong>
            <span>The synchronization service has no unexpired sessions for this account.</span>
          </div>
        ) : null}
        {refreshing && sessions.length === 0 ? (
          <div className="loading-catalog">Downloading and decrypting sessions…</div>
        ) : null}
      </section>
    </main>
  );
}

function HerdrTerminal({
  syncClient,
  syncedSession,
  onBack,
}: {
  syncClient: SyncClient;
  syncedSession: SyncedSession;
  onBack(): void;
}) {
  const { ref, write, focus } = useTerminal();
  const latestSize = useRef<{ columns: number; rows: number } | undefined>(undefined);
  const protocolRef = useRef<HerdrTuiProtocol | undefined>(undefined);
  const transportRef = useRef<IrohTransport | undefined>(undefined);
  const [connected, setConnected] = useState(false);
  const [mouseCapture, setMouseCapture] = useState(false);
  const [isPhone] = useState(() => isPhoneUserAgent(window.navigator.userAgent));
  const [status, setStatus] = useState("connecting");

  const recordId = syncedSession?.record_id;
  const sessionName = syncedSession?.session;

  useEffect(() => {
    let disposed = false;
    const abortController = new AbortController();
    let protocol: HerdrTuiProtocol | undefined;
    let transport: IrohTransport | undefined;

    const handleProtocolBytes = (bytes: Uint8Array) => {
      if (protocol === undefined) return;
      for (const protocolEvent of protocol.pushServerBytes(bytes)) {
        if (protocolEvent.type === "output") {
          write(protocolEvent.data);
          continue;
        }

        const message = protocolEvent.message;
        if (message.type === "ready") {
          setConnected(true);
          setStatus(
            `connected over Iroh to Herdr TUI protocol ${String(message.protocol ?? "unknown")}`,
          );
          focus();
        }
        if (message.type === "exit") {
          setStatus(`Herdr server: ${String(message.reason ?? "disconnected")}`);
        }
        if (message.type === "window_title") {
          document.title =
            typeof message.title === "string"
              ? message.title
              : "Herdr browser Iroh TUI";
        }
        if (message.type === "mouse_capture") {
          setMouseCapture(message.enabled === true);
        }
      }
    };

    const connect = async () => {
      if (recordId === undefined || sessionName === undefined) {
        throw new Error("synchronized session is unavailable");
      }
      setStatus("loading Herdr protocol WASM");
      protocol = await HerdrTuiProtocol.load();
      if (disposed) return;
      protocolRef.current = protocol;

      const connectionTarget = syncClient.connectionFor({
        record_id: recordId,
        session: sessionName,
      });
      setStatus("connecting to Iroh relay");
      transport = await IrohTransport.connect(
        connectionTarget,
        undefined,
        abortController.signal,
      );
      if (disposed) {
        await transport.close();
        return;
      }
      transportRef.current = transport;

      const activeTransport = transport;
      try {
        const size = latestSize.current ?? { columns: 120, rows: 36 };
        await activeTransport.send(protocol.encodeHello(size.columns, size.rows));
        setStatus("negotiating Herdr TUI protocol");

        while (!disposed) {
          const bytes = await activeTransport.receive();
          if (bytes === undefined) break;
          handleProtocolBytes(bytes);
        }
      } finally {
        if (transportRef.current === activeTransport) {
          transportRef.current = undefined;
        }
        await activeTransport.close();
        if (transport === activeTransport) transport = undefined;
      }

      if (!disposed) {
        setConnected(false);
        setStatus((current) =>
          current.startsWith("Herdr server:") ? current : "disconnected",
        );
      }
    };

    void connect().catch((error: unknown) => {
      if (disposed) return;
      setConnected(false);
      setStatus(
        error instanceof Error ? error.message : "unable to start Iroh protocol client",
      );
      void transport?.close();
    });

    return () => {
      disposed = true;
      abortController.abort();
      setConnected(false);
      const activeTransport = transport;
      transport = undefined;
      if (transportRef.current === activeTransport) transportRef.current = undefined;
      if (protocolRef.current === protocol) protocolRef.current = undefined;
      if (activeTransport !== undefined) {
        void (async () => {
          try {
            if (protocol !== undefined) {
              await Promise.race([
                activeTransport.send(protocol.encodeDetach()),
                new Promise<void>((resolve) =>
                  window.setTimeout(resolve, DETACH_TIMEOUT_MS),
                ),
              ]);
            }
          } catch {
            // Detach is best-effort during navigation or mobile suspension.
          } finally {
            await activeTransport.close();
          }
        })();
      }
    };
  }, [focus, recordId, sessionName, syncClient, write]);

  const sendBytes = (bytes: Uint8Array) => {
    const transport = transportRef.current;
    if (!connected || transport === undefined) return;
    void transport.send(bytes).catch((error: unknown) => {
      setStatus(error instanceof Error ? error.message : "unable to send tunnel data");
    });
  };

  const sendInput = (data: string) => {
    const protocol = protocolRef.current;
    if (protocol !== undefined) sendBytes(protocol.encodeInput(data));
  };

  const sendEnhancedKey = (event: ReactKeyboardEvent<HTMLDivElement>) => {
    if (!event.ctrlKey || !event.altKey || !connected) return;

    const data = encodeCsiUKey(event.code, event);
    if (data === undefined) return;

    event.preventDefault();
    event.stopPropagation();
    sendInput(data);
  };

  const sendMouseEvent = (
    event: ReactMouseEvent<HTMLDivElement>,
    pressed: boolean,
  ) => {
    if (event.shiftKey || !mouseCapture || !connected) return;

    const grid = event.currentTarget.querySelector<HTMLElement>(".term-grid");
    const size = latestSize.current;
    if (grid === null || size === undefined) return;

    const cell = terminalCellFromPoint(
      grid,
      event.clientX,
      event.clientY,
      size.columns,
      size.rows,
    );
    if (cell === undefined) return;

    const data = encodeSgrMouseEvent(event.button, pressed, cell, event);
    if (data === undefined) return;

    event.preventDefault();
    focus();
    sendInput(data);
  };

  return (
    <main className={`direct-shell${isPhone ? " direct-shell--phone" : ""}`}>
      <header>
        <div className="terminal-heading">
          {onBack === undefined ? null : (
            <button
              type="button"
              className="back-button"
              aria-label="Back to sessions"
              onClick={onBack}
            >
              ← Sessions
            </button>
          )}
          <div>
            <strong>{sessionName ?? "Herdr browser Iroh TUI"}</strong>
            <span>{status}</span>
          </div>
        </div>
        <code>Iroh relay transport</code>
      </header>
      <Terminal
        ref={ref}
        aria-label="Real Herdr terminal"
        className="direct-terminal"
        autoResize
        cursorBlink
        onReady={(terminal) => {
          latestSize.current ??= {
            columns: terminal.cols,
            rows: terminal.rows,
          };
          focus();
        }}
        onKeyDownCapture={sendEnhancedKey}
        onMouseDown={(event) => sendMouseEvent(event, true)}
        onMouseUp={(event) => sendMouseEvent(event, false)}
        onContextMenu={(event) => event.preventDefault()}
        onData={sendInput}
        onResize={(columns, rows) => {
          latestSize.current = { columns, rows };
          const protocol = protocolRef.current;
          if (protocol !== undefined) {
            sendBytes(protocol.encodeResize(columns, rows));
          }
        }}
      />
      {isPhone ? (
        <nav className="mobile-actions" aria-label="Herdr mobile actions">
          {DEFAULT_MOBILE_ACTIONS.map((action) => (
            <button
              key={action.label}
              type="button"
              disabled={!connected}
              onClick={() => {
                sendInput(action.input);
                focus();
              }}
            >
              {action.label}
            </button>
          ))}
        </nav>
      ) : null}
    </main>
  );
}

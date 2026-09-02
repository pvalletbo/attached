import {
  Action,
  ActionPanel,
  Color,
  Form,
  getPreferenceValues,
  Icon,
  Keyboard,
  List,
  open,
  openExtensionPreferences,
  showToast,
  Toast,
} from "@raycast/api";
import { useCallback, useEffect, useRef, useState } from "react";

import {
  CatalogCommandError,
  EncryptionPasswordProvider,
  loadSessionCatalog,
  MAX_PASSWORD_BYTES,
  resolveAttachedExecutable,
} from "./attached";
import { AttachedSession, lastPublishSummary, versionSummary } from "./catalog";
import { DisplayError, displayError } from "./errors";
import { launchAttachedSession } from "./terminal";

type Preferences = {
  encryptionPasswordProvider: EncryptionPasswordProvider;
  attachedExecutablePath?: string;
};

type CatalogState =
  | { kind: "password"; error?: DisplayError }
  | { kind: "loading" }
  | { kind: "sessions"; executable: string; sessions: AttachedSession[] }
  | { kind: "error"; error: DisplayError };

export default function SearchSessions() {
  const preferences = getPreferenceValues<Preferences>();
  const provider: EncryptionPasswordProvider =
    preferences.encryptionPasswordProvider === "1password" ? "1password" : "password";
  const [state, setState] = useState<CatalogState>(() =>
    provider === "password" ? { kind: "password" } : { kind: "loading" },
  );
  const activeRefresh = useRef<AbortController | undefined>(undefined);
  const refreshGeneration = useRef(0);

  const refresh = useCallback(
    async (password?: Buffer) => {
      const generation = ++refreshGeneration.current;
      activeRefresh.current?.abort();
      const controller = new AbortController();
      activeRefresh.current = controller;
      setState({ kind: "loading" });

      try {
        const executable = resolveAttachedExecutable(preferences.attachedExecutablePath);
        const sessions = await loadSessionCatalog(executable, provider, password, {
          signal: controller.signal,
        });
        if (generation === refreshGeneration.current) {
          setState({ kind: "sessions", executable, sessions });
        }
      } catch (error) {
        const wasAborted = error instanceof CatalogCommandError && error.kind === "aborted";
        if (generation !== refreshGeneration.current || wasAborted) {
          return;
        }
        const rendered = displayError(error, provider);
        setState(provider === "password" ? { kind: "password", error: rendered } : { kind: "error", error: rendered });
      } finally {
        password?.fill(0);
      }
    },
    [preferences.attachedExecutablePath, provider],
  );

  useEffect(() => {
    if (provider === "1password") {
      void refresh();
    }
    return () => {
      refreshGeneration.current += 1;
      activeRefresh.current?.abort();
    };
  }, [provider, refresh]);

  const requestRefresh = useCallback(() => {
    if (provider === "password") {
      activeRefresh.current?.abort();
      setState({ kind: "password" });
    } else {
      void refresh();
    }
  }, [provider, refresh]);

  if (state.kind === "password") {
    return <PasswordForm error={state.error} onUnlock={refresh} />;
  }
  if (state.kind === "loading") {
    return <LoadingView />;
  }
  if (state.kind === "error") {
    return <ErrorView error={state.error} provider={provider} onRetry={requestRefresh} />;
  }
  return (
    <SessionList
      executable={state.executable}
      provider={provider}
      sessions={state.sessions}
      onRefresh={requestRefresh}
    />
  );
}

function PasswordForm({ error, onUnlock }: { error?: DisplayError; onUnlock: (password: Buffer) => Promise<void> }) {
  const [password, setPassword] = useState("");
  const [fieldError, setFieldError] = useState<string>();

  async function submit() {
    const secret = Buffer.from(password, "utf8");
    if (secret.byteLength === 0) {
      setFieldError("Enter your Attached encryption password.");
      return;
    }
    if (secret.byteLength > MAX_PASSWORD_BYTES) {
      secret.fill(0);
      setFieldError(`The password cannot exceed ${MAX_PASSWORD_BYTES} UTF-8 bytes.`);
      return;
    }

    setFieldError(undefined);
    setPassword("");
    await onUnlock(secret);
  }

  return (
    <Form
      navigationTitle="Unlock Attached"
      actions={
        <ActionPanel>
          <Action.SubmitForm title="Load Sessions" icon={Icon.LockUnlocked} onSubmit={submit} />
          <Action title="Open Extension Preferences" icon={Icon.Gear} onAction={openExtensionPreferences} />
        </ActionPanel>
      }
    >
      <Form.Description
        title="Attached Sessions"
        text="Enter the encryption password for this Mac's Attached state. It is sent only to attached over standard input and is not stored by the extension."
      />
      {error ? <Form.Description title={error.title} text={error.message} /> : null}
      <Form.PasswordField
        id="encryptionPassword"
        title="Encryption Password"
        placeholder="Password"
        value={password}
        error={fieldError}
        onChange={(value) => {
          setPassword(value);
          if (fieldError !== undefined) {
            setFieldError(undefined);
          }
        }}
      />
    </Form>
  );
}

function LoadingView() {
  return (
    <List isLoading searchBarPlaceholder="Refreshing Attached sessions…">
      <List.Item icon={Icon.ArrowClockwise} title="Refreshing Attached Sessions" />
    </List>
  );
}

function ErrorView({
  error,
  provider,
  onRetry,
}: {
  error: DisplayError;
  provider: EncryptionPasswordProvider;
  onRetry: () => void;
}) {
  return (
    <List>
      <List.EmptyView
        icon={{ source: Icon.Warning, tintColor: Color.Red }}
        title={error.title}
        description={error.message}
        actions={
          <ActionPanel>
            <Action
              title="Retry"
              icon={Icon.ArrowClockwise}
              shortcut={Keyboard.Shortcut.Common.Refresh}
              onAction={onRetry}
            />
            {provider === "1password" ? (
              <Action title="Open 1Password" icon={Icon.Lock} onAction={openOnePassword} />
            ) : null}
            <Action title="Open Extension Preferences" icon={Icon.Gear} onAction={openExtensionPreferences} />
            {error.kind === "missing" ? (
              <Action.OpenInBrowser
                title="Open Attached Installation Instructions"
                url="https://github.com/pvalletbo/attached#install"
              />
            ) : null}
          </ActionPanel>
        }
      />
    </List>
  );
}

function SessionList({
  executable,
  provider,
  sessions,
  onRefresh,
}: {
  executable: string;
  provider: EncryptionPasswordProvider;
  sessions: AttachedSession[];
  onRefresh: () => void;
}) {
  return (
    <List searchBarPlaceholder="Search hosts and sessions…">
      {sessions.length === 0 ? (
        <List.EmptyView
          icon={Icon.Terminal}
          title="No Synchronized Sessions"
          description="Attached did not find any remote Herdr sessions."
          actions={<CommonActions provider={provider} onRefresh={onRefresh} />}
        />
      ) : (
        <List.Section title="Synchronized Sessions" subtitle={String(sessions.length)}>
          {sessions.map((session) => (
            <SessionItem
              key={session.target}
              executable={executable}
              provider={provider}
              session={session}
              onRefresh={onRefresh}
            />
          ))}
        </List.Section>
      )}
    </List>
  );
}

function SessionItem({
  executable,
  provider,
  session,
  onRefresh,
}: {
  executable: string;
  provider: EncryptionPasswordProvider;
  session: AttachedSession;
  onRefresh: () => void;
}) {
  const attachedVersion = versionSummary(session.attachedVersion);
  const herdrVersion = versionSummary(session.herdrVersion);
  const published = lastPublishSummary(session.publishedAt);

  async function connect() {
    const toast = await showToast({
      style: Toast.Style.Animated,
      title: "Opening Terminal…",
      message: session.target,
    });
    try {
      await launchAttachedSession(executable, provider, session.target);
      toast.style = Toast.Style.Success;
      toast.title = "Opened in Terminal";
    } catch {
      toast.style = Toast.Style.Failure;
      toast.title = "Could Not Open Terminal";
      toast.message = "Open Terminal manually and run attached attach for this session.";
    }
  }

  return (
    <List.Item
      id={session.target}
      icon={Icon.Terminal}
      title={session.host}
      subtitle={session.session}
      keywords={[session.target, session.host, session.session]}
      accessories={[
        { text: `Attached ${attachedVersion}`, tooltip: "Remote Attached version" },
        { text: `Herdr ${herdrVersion}`, tooltip: "Remote Herdr version" },
        { text: published, tooltip: "Last published" },
      ]}
      actions={
        <ActionPanel>
          <Action title="Connect in Terminal" icon={Icon.Terminal} onAction={connect} />
          <Action.CopyToClipboard
            title="Copy Session Target"
            content={session.target}
            shortcut={Keyboard.Shortcut.Common.Copy}
          />
          <CommonActions provider={provider} onRefresh={onRefresh} />
        </ActionPanel>
      }
    />
  );
}

function CommonActions({ provider, onRefresh }: { provider: EncryptionPasswordProvider; onRefresh: () => void }) {
  return (
    <ActionPanel.Section title="Attached">
      <Action
        title={provider === "password" ? "Enter Password Again and Refresh" : "Refresh Sessions"}
        icon={Icon.ArrowClockwise}
        shortcut={Keyboard.Shortcut.Common.Refresh}
        onAction={onRefresh}
      />
      {provider === "1password" ? <Action title="Open 1Password" icon={Icon.Lock} onAction={openOnePassword} /> : null}
      <Action title="Open Extension Preferences" icon={Icon.Gear} onAction={openExtensionPreferences} />
    </ActionPanel.Section>
  );
}

async function openOnePassword() {
  try {
    await open("onepassword://");
  } catch {
    await open("https://1password.com/downloads/mac/");
  }
}

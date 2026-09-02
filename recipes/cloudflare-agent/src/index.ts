import { getSandbox, Sandbox, type Process } from "@cloudflare/sandbox";
import { Agent, callable, routeAgentRequest } from "agents";

import {
  computerInvocation,
  deriveHostLabel,
  errorMessage,
  isAuthorized,
  json,
  lastPathSegment,
  truncateOutput,
  validateCommand,
} from "./http.mjs";

export { Sandbox };

interface Env extends Cloudflare.Env {
  Sandbox: DurableObjectNamespace<Sandbox>;
  HerdrAgent: DurableObjectNamespace<HerdrAgent>;
  ATTACHED_PUBLISH_BUNDLE: string;
  ATTACHED_LOCAL_PASSWORD: string;
  ATTACHED_HOST_LABEL_PREFIX: string;
  AGENT_API_TOKEN: string;
  ENABLE_COMPUTER_TOOL: string;
}

type PublisherState = {
  status: "stopped" | "starting" | "running" | "failed";
  hostLabel?: string;
  startedAt?: string;
  lastError?: string;
};

const PROCESS_ID = "attached-herdr-publisher";
const SANDBOX_ENV = {
  HOME: "/workspace/home",
  LANG: "C.UTF-8",
  SHELL: "/bin/bash",
  TERM: "xterm-256color",
  HERDR_STARTUP_CWD: "/workspace",
  ATTACHED_STATE_DIR: "/workspace/.attached",
} as const;

function processSummary(process: Process | null) {
  if (!process) return { status: "stopped" as const };
  return {
    id: process.id,
    pid: process.pid,
    status: process.status,
    startedAt: process.startTime.toISOString(),
    exitCode: process.exitCode,
  };
}

export class HerdrAgent extends Agent<Env, PublisherState> {
  override initialState: PublisherState = { status: "stopped" };

  private sandbox() {
    return getSandbox(this.env.Sandbox, this.name, {
      keepAlive: true,
      normalizeId: true,
      transport: "rpc",
      containerTimeouts: { portReadyTimeoutMS: 120_000 },
    });
  }

  private hostLabel() {
    return deriveHostLabel(this.env.ATTACHED_HOST_LABEL_PREFIX, this.name);
  }

  @callable({ description: "Start a headless Herdr session and publish it through Attached" })
  async startHerdr() {
    if (!this.env.ATTACHED_PUBLISH_BUNDLE || !this.env.ATTACHED_LOCAL_PASSWORD) {
      throw new Error("Attached publisher secrets are not configured");
    }
    const sandbox = this.sandbox();
    const hostLabel = this.hostLabel();
    try {
      const existing = await sandbox.getProcess(PROCESS_ID);
      if (existing && ["starting", "running"].includes(existing.status)) {
        if (this.state.status !== "running") {
          await existing.waitForLog("Serving synchronized Herdr sessions", 120_000);
        }
        this.setState({
          status: "running",
          hostLabel,
          startedAt: existing.startTime.toISOString(),
        });
        return { hostLabel, process: processSummary(existing) };
      }

      this.setState({ status: "starting", hostLabel });
      await sandbox.cleanupCompletedProcesses();
      const process = await sandbox.startProcess(
        "/usr/local/bin/attached-herdr-entrypoint",
        {
          processId: PROCESS_ID,
          autoCleanup: false,
          cwd: "/workspace",
          env: {
            ...SANDBOX_ENV,
            ATTACHED_PUBLISH_BUNDLE: this.env.ATTACHED_PUBLISH_BUNDLE,
            ATTACHED_LOCAL_PASSWORD: this.env.ATTACHED_LOCAL_PASSWORD,
            ATTACHED_HOST_LABEL: hostLabel,
            ATTACHED_HEALTH_PORT: "0",
            ATTACHED_RUN_AS_UID: "10001",
            ATTACHED_RUN_AS_GID: "10001",
          },
        },
      );
      await process.waitForLog("Serving synchronized Herdr sessions", 120_000);
      const startedAt = process.startTime.toISOString();
      this.setState({ status: "running", hostLabel, startedAt });
      return { hostLabel, process: processSummary(process) };
    } catch {
      await sandbox.destroy().catch(async () => {
        await sandbox.setKeepAlive(false).catch(() => undefined);
      });
      this.setState({
        status: "failed",
        hostLabel,
        lastError: "publisher startup failed",
      });
      throw new Error("publisher startup failed");
    }
  }

  @callable({ description: "Inspect the Attached publisher process in this Agent sandbox" })
  async herdrStatus() {
    if (!["starting", "running"].includes(this.state.status)) {
      return {
        hostLabel: this.hostLabel(),
        process: processSummary(null),
        durableState: this.state,
      };
    }

    const sandbox = this.sandbox();
    const process = await sandbox.getProcess(PROCESS_ID);
    const summary = processSummary(process);
    if (!process || !["starting", "running"].includes(process.status)) {
      await sandbox.destroy().catch(async () => {
        await sandbox.setKeepAlive(false).catch(() => undefined);
      });
      this.setState({
        status: "failed",
        hostLabel: this.hostLabel(),
        startedAt: this.state.startedAt,
        lastError: "publisher process is not running",
      });
    }
    return {
      hostLabel: this.hostLabel(),
      process: summary,
      durableState: this.state,
    };
  }

  @callable({ description: "Stop the publisher and destroy its ephemeral sandbox" })
  async stopHerdr() {
    if (this.state.status === "stopped") {
      return { status: "stopped" as const };
    }
    const sandbox = this.sandbox();
    try {
      const process = await sandbox.getProcess(PROCESS_ID);
      if (process && ["starting", "running"].includes(process.status)) {
        await process.kill("SIGTERM");
        await process.waitForExit(15_000).catch(() => undefined);
      }
    } finally {
      await sandbox.destroy();
      this.setState({ status: "stopped", hostLabel: this.hostLabel() });
    }
    return { status: "stopped" as const };
  }

  @callable({ description: "Run an opt-in shell command in the isolated Herdr workspace" })
  async computer(command: string) {
    if (this.env.ENABLE_COMPUTER_TOOL !== "true") {
      throw new Error("computer tool is disabled; set ENABLE_COMPUTER_TOOL=true to opt in");
    }
    const invocation = computerInvocation(command);
    await this.startHerdr();
    const result = await this.sandbox().exec(invocation.command, {
      cwd: "/workspace",
      timeout: 30_000,
      env: { ...SANDBOX_ENV, ...invocation.env },
    });
    return {
      success: result.success,
      exitCode: result.exitCode,
      stdout: truncateOutput(result.stdout),
      stderr: truncateOutput(result.stderr),
    };
  }

  override async onRequest(request: Request): Promise<Response> {
    const action = lastPathSegment(new URL(request.url).pathname);
    try {
      if (action === "publisher" && request.method === "PUT") {
        return json(await this.startHerdr(), 201);
      }
      if (action === "publisher" && request.method === "GET") {
        return json(await this.herdrStatus());
      }
      if (action === "publisher" && request.method === "DELETE") {
        return json(await this.stopHerdr());
      }
      if (action === "computer" && request.method === "POST") {
        const body: unknown = await request.json();
        const command =
          typeof body === "object" && body !== null && "command" in body
            ? (body as { command?: unknown }).command
            : undefined;
        return json(await this.computer(validateCommand(command)));
      }
      return json(
        {
          error: "Use PUT/GET/DELETE .../publisher or POST .../computer",
        },
        404,
      );
    } catch (error: unknown) {
      if (error instanceof TypeError || error instanceof SyntaxError) {
        return json({ error: errorMessage(error) }, 400);
      }
      console.error(
        "Herdr Agent operation failed",
        error instanceof Error ? error.name : "UnknownError",
      );
      return json({ error: "Herdr Agent operation failed" }, 500);
    }
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (new URL(request.url).pathname === "/healthz") {
      return json({ ok: true });
    }
    if (!isAuthorized(request, env.AGENT_API_TOKEN)) {
      return new Response("Unauthorized", {
        status: 401,
        headers: {
          "cache-control": "no-store",
          "www-authenticate": "Bearer",
        },
      });
    }
    return (
      (await routeAgentRequest(request, env)) ??
      json({ error: "Expected /agents/herdr-agent/:name/..." }, 404)
    );
  },
} satisfies ExportedHandler<Env>;

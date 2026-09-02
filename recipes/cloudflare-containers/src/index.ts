import { Container } from "@cloudflare/containers";

import { isAuthorized, json } from "./http.mjs";

interface Env {
  HERDR_CONTAINER: DurableObjectNamespace<HerdrContainer>;
  ATTACHED_PUBLISH_BUNDLE: string;
  ATTACHED_LOCAL_PASSWORD: string;
  ATTACHED_HOST_LABEL: string;
  CONTROL_API_TOKEN: string;
}

const CONTAINER_NAME = "primary";

function required(value: string | undefined, name: string): string {
  if (!value) throw new Error(`${name} is not configured`);
  return value;
}

export class HerdrContainer extends Container<Env> {
  override defaultPort = 8080;
  override requiredPorts = [8080];
  override sleepAfter = "10m";
  override enableInternet = true;
  override pingEndpoint = "localhost/healthz";

  constructor(ctx: DurableObjectState<{}>, env: Env) {
    super(ctx, env);
    this.envVars = {
      ATTACHED_PUBLISH_BUNDLE: required(
        env.ATTACHED_PUBLISH_BUNDLE,
        "ATTACHED_PUBLISH_BUNDLE",
      ),
      ATTACHED_LOCAL_PASSWORD: required(
        env.ATTACHED_LOCAL_PASSWORD,
        "ATTACHED_LOCAL_PASSWORD",
      ),
      ATTACHED_HOST_LABEL: required(env.ATTACHED_HOST_LABEL, "ATTACHED_HOST_LABEL"),
    };
  }

  // Attached traffic reaches the process over Iroh and cannot renew the Worker
  // activity timer. Keep a started publisher alive until the explicit DELETE.
  override async onActivityExpired(): Promise<void> {
    this.renewActivityTimeout();
  }

  override onError(error: unknown): never {
    console.error(
      "Herdr container runtime failed",
      error instanceof Error ? error.name : "UnknownError",
    );
    throw new Error("Herdr container runtime failed");
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/healthz") {
      return json({ ok: true });
    }

    if (!isAuthorized(request, env.CONTROL_API_TOKEN)) {
      return new Response("Unauthorized", {
        status: 401,
        headers: {
          "cache-control": "no-store",
          "www-authenticate": "Bearer",
        },
      });
    }

    if (url.pathname !== "/session") {
      return json({ error: "Use PUT, GET, or DELETE /session" }, 404);
    }

    const container = env.HERDR_CONTAINER.getByName(CONTAINER_NAME);
    try {
      if (request.method === "PUT") {
        try {
          await container.startAndWaitForPorts({
            cancellationOptions: {
              instanceGetTimeoutMS: 120_000,
              portReadyTimeoutMS: 180_000,
            },
          });
          const ready = await container.fetch(
            new Request("http://container/healthz"),
          );
          if (!ready.ok) {
            await container.stop("SIGTERM");
            return json({ error: "Herdr publisher did not become healthy" }, 503);
          }
          return json(
            {
              status: "running",
              hostLabel: env.ATTACHED_HOST_LABEL,
              lifecycle: "Call DELETE /session when finished",
            },
            201,
          );
        } catch (error: unknown) {
          await container.stop("SIGTERM").catch(() => undefined);
          throw error;
        }
      }

      if (request.method === "GET") {
        return json(await container.getState());
      }

      if (request.method === "DELETE") {
        await container.stop("SIGTERM");
        return json({ status: "stopped" });
      }

      return new Response("Method Not Allowed", {
        status: 405,
        headers: {
          allow: "PUT, GET, DELETE",
          "cache-control": "no-store",
        },
      });
    } catch (error: unknown) {
      console.error(
        "Herdr container operation failed",
        error instanceof Error ? error.name : "UnknownError",
      );
      return json({ error: "Herdr container operation failed" }, 500);
    }
  },
} satisfies ExportedHandler<Env>;

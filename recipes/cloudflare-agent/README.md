# Cloudflare Agent with a Herdr Sandbox

> **AI contribution notice:** This recipe document was created with assistance from an AI coding agent and is intended for human review.

This example combines an Agents SDK Durable Object with a Sandbox SDK Container. Each Agent name owns one isolated Linux environment, starts a headless Herdr publisher as a managed background process, and retains small lifecycle metadata in Agent state.

Sandbox is used instead of Browser Rendering because Herdr needs a filesystem, processes, Unix sockets, PTYs, and a long-running terminal server.

## Configure and deploy

A Cloudflare account with Sandbox access, a running local Docker daemon, and Node.js `22.18.0` or newer in the Node 22 LTS line (or Node `24.11.0`+) are required. Install the pinned workspace dependencies:

```sh
cd recipes
corepack enable
pnpm install --frozen-lockfile
cd cloudflare-agent
```

For local development, copy `.dev.vars.example` to `.dev.vars` and replace its placeholders. For production, generate a separate API token with `openssl rand -hex 32` and configure three interactive Worker secrets:

```sh
pnpm exec wrangler secret put ATTACHED_PUBLISH_BUNDLE
pnpm exec wrangler secret put ATTACHED_LOCAL_PASSWORD
pnpm exec wrangler secret put AGENT_API_TOKEN
pnpm deploy
```

`@cloudflare/sandbox` and the `cloudflare/sandbox` base image are both pinned to `0.12.9`; those versions must remain synchronized. The image adds checksum-verified Herdr `0.8.2` and Attached `0.2.3` without replacing Sandbox's root control-server entrypoint. Publisher and computer-tool processes irreversibly drop to the dedicated UID/GID `10001` before running user workloads.

## Use the Agent

The default Agents route is `/agents/herdr-agent/:name`. A distinct lowercase name creates a distinct Agent and Sandbox:

```sh
read -r -s AGENT_API_TOKEN
export AGENT_API_TOKEN
BASE_URL=https://attached-herdr-agent.YOUR_SUBDOMAIN.workers.dev
AGENT_URL="$BASE_URL/agents/herdr-agent/demo"

curl --fail-with-body -X PUT \
  -H "Authorization: Bearer $AGENT_API_TOKEN" \
  "$AGENT_URL/publisher"

curl --fail-with-body \
  -H "Authorization: Bearer $AGENT_API_TOKEN" \
  "$AGENT_URL/publisher"
```

The `demo` Agent publishes `cloudflare-agent-demo/default`. Its methods `startHerdr`, `herdrStatus`, `stopHerdr`, and `computer` are also marked `@callable()` for an Agents SDK client or a model/tool layer.

Destroy the Sandbox explicitly when finished:

```sh
curl --fail-with-body -X DELETE \
  -H "Authorization: Bearer $AGENT_API_TOKEN" \
  "$AGENT_URL/publisher"
```

`keepAlive: true` is intentional for interactive terminal sessions and incurs Container usage until destruction. Every distinct Agent name can create another separately billable Sandbox, so keep the bearer token tightly scoped, add rate limits or an Agent-name allowlist for multi-user deployments, and destroy every name you start.

## Optional computer tool

The recipe includes a bounded shell tool backed by `sandbox.exec()`. It is disabled by default. To demonstrate a model or trusted client operating the Herdr workspace, set `ENABLE_COMPUTER_TOOL` to `"true"` in `wrangler.jsonc`, redeploy, and call:

```sh
curl --fail-with-body -X POST \
  -H "Authorization: Bearer $AGENT_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"command":"herdr workspace list"}' \
  "$AGENT_URL/computer"
```

Enabling this is equivalent to granting shell access as the unprivileged runtime user inside the Sandbox. The endpoint limits command size, execution time, and returned output, but it does not constrain shell semantics. Keep bearer authentication in front of all Agent routes, add human approval before model-initiated side effects, and never give an untrusted model secrets it does not need.

The example deliberately does not select an LLM provider. Its callable methods are a model-neutral tool surface that can be connected to Workers AI, AI Gateway, or another provider without changing the Attached publisher lifecycle.

## Persistence

Agent state survives Durable Object hibernation. Sandbox files and Herdr processes do not survive an explicit destroy or instance replacement. The `/workspace` layout makes it possible to add Sandbox backups or an R2 mount, but this ready-to-use recipe leaves the host truly ephemeral.

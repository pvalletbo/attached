# Cloudflare Workers backed by Containers

> **AI contribution notice:** This recipe document was created with assistance from an AI coding agent and is intended for human review.

A Worker controls one Cloudflare Container. The Container runs the standard recipe image; Attached publishes the headless Herdr session over Iroh. The public Worker exposes only an authenticated lifecycle API, not the terminal itself.

## Configure

Cloudflare Containers, a running local Docker daemon, and Node.js `22.18.0` or newer in the Node 22 LTS line (or Node `24.11.0`+) are required. Install the pinned workspace dependencies:

```sh
cd recipes
corepack enable
pnpm install --frozen-lockfile
cd cloudflare-containers
```

For local development, copy `.dev.vars.example` to `.dev.vars` and replace all placeholders. `.dev.vars` is ignored by Git.

For production, generate a separate control token with `openssl rand -hex 32` and set three Worker secrets interactively:

```sh
pnpm exec wrangler secret put ATTACHED_PUBLISH_BUNDLE
pnpm exec wrangler secret put ATTACHED_LOCAL_PASSWORD
pnpm exec wrangler secret put CONTROL_API_TOKEN
```

Set the non-secret `ATTACHED_HOST_LABEL` in `wrangler.jsonc`, then deploy:

```sh
pnpm deploy
```

The custom image path resolves to [`../docker/Dockerfile`](../docker/Dockerfile), so the same reviewed runtime is used by Docker and Cloudflare.

## Start, inspect, and stop

Use a long random control token and the deployed Worker URL:

```sh
read -r -s CONTROL_API_TOKEN
export CONTROL_API_TOKEN
BASE_URL=https://attached-herdr-container.YOUR_SUBDOMAIN.workers.dev

curl --fail-with-body -X PUT \
  -H "Authorization: Bearer $CONTROL_API_TOKEN" \
  "$BASE_URL/session"

curl --fail-with-body \
  -H "Authorization: Bearer $CONTROL_API_TOKEN" \
  "$BASE_URL/session"

curl --fail-with-body -X DELETE \
  -H "Authorization: Bearer $CONTROL_API_TOKEN" \
  "$BASE_URL/session"
```

Once `PUT` succeeds, attach to `cloudflare-container/default` from a machine holding the download-only bundle.

## Lifecycle and cost

Attached/Iroh traffic bypasses the Worker, so it cannot renew the Container class's request-activity timer. `HerdrContainer.onActivityExpired()` deliberately renews that timer. A started instance therefore remains billable until `DELETE /session`, a deployment replaces it, or Cloudflare terminates it. Always issue `DELETE` when finished.

Container disk is ephemeral. Sleep/resume may retain the filesystem, but replacement and rollout do not. The recipe uses one `standard-1` instance and one fixed Durable Object name to prevent accidental fan-out with the same host label.

The Worker forwards the publish bundle and local password to the Container only as runtime environment variables. The entrypoint immediately stages and removes them from descendant environments. They are not Wrangler plaintext vars or Docker build arguments.

# Attached Herdr deployment recipes

> **AI contribution notice:** This recipe document was created with assistance from an AI coding agent and is intended for human review.

These examples start a supervised, headless Herdr session and publish it through Attached. The host needs outbound network access, but no public SSH port: Attached authenticates the downloader and carries the terminal over Iroh.

A plain Cloudflare Worker cannot host Herdr because a Workers isolate does not provide its required long-lived processes, PTYs, filesystem, or Unix sockets. The Cloudflare recipes therefore place the runtime in either a Container or a Sandbox and use a Worker only as the authenticated control plane.

| Recipe | Runtime | Start/stop model |
| --- | --- | --- |
| [`docker/`](docker/) | Docker or any OCI host | Container lifetime |
| [`cloudflare-containers/`](cloudflare-containers/) | Cloudflare Worker + Container | Authenticated HTTP API |
| [`cloudflare-agent/`](cloudflare-agent/) | Cloudflare Agents SDK + Sandbox SDK | Per-Agent Sandbox and callable tools |
| [`remote-hosts/`](remote-hosts/) | Kubernetes, GitHub Actions, and other ephemeral OCI hosts | Platform-specific |

## Create the credentials once

On a trusted workstation with Attached installed:

```sh
attached account create
attached account export --type publish --output publish.bundle
attached account export --type download --output download.bundle
openssl rand -base64 48 > local-password
chmod 600 publish.bundle download.bundle local-password
```

Give a deployment only `publish.bundle` and a generated local encryption password. Keep the account-creator state and `download.bundle` away from the remote host. Use a distinct local password for each deployment rather than an account or model-provider password. It encrypts Attached state at rest, so keep that deployment's value stable anywhere that preserves the state directory.

Import the download-only credential on each controlling workstation:

```sh
attached account import --bundle-file download.bundle
attached sessions list
attached attach HOST_LABEL/default
```

## Runtime contract

Every recipe uses the same runtime behavior:

- The Debian and Cloudflare Sandbox parent images are pinned by digest; Herdr `0.8.2` and Attached `0.2.3` are downloaded from their release pages and verified against architecture-specific SHA-256 digests.
- `attached serve` starts the default Herdr server headlessly when no session exists, then publishes it as `HOST_LABEL/default`.
- A tiny HTTP endpoint becomes available at `/healthz` only after the first catalog publication.
- Environment-injected secrets are copied into owner-only temporary files, removed from the long-running child environment by re-exec, and never baked into an image. A platform's control plane may still retain injected values, so restrict deployment-inspection access and prefer mounted secret files where available.
- `SIGTERM`, `SIGINT`, and `SIGHUP` are converted into an orderly Attached interrupt; the Herdr server is then stopped.

The controller's Herdr version should match the pinned runtime version. Upgrade by reviewing and updating release versions, checksums, package versions, and image digests together, then rebuild instead of mutating a running ephemeral instance.

## Ephemeral means disposable

Live pane processes and PTYs exist only for the lifetime of their container or Sandbox. A platform sleep that preserves the same instance may resume them, but replacement, rollout, eviction, or explicit destruction always terminates them. Persistent volumes can preserve workspace files and on-disk metadata across a restart; anything on ephemeral storage is lost. Attached publishes reachability—it is neither process checkpointing nor filesystem backup.

Treat the publish bundle as an account-sensitive credential and the download bundle as remote-shell-equivalent access. Use platform secret stores, protect every management endpoint, stop idle instances explicitly, and rotate credentials after suspected exposure. Any model, source-control, or package-registry credential supplied to a coding pane is readable by commands in that runtime, so prefer short-lived, repository-scoped, least-privilege tokens and never reuse the control-plane bearer token.

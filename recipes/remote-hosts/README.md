# Other remote ephemeral hosts

> **AI contribution notice:** This recipe document was created with assistance from an AI coding agent and is intended for human review.

The standard [`../docker`](../docker/) image works anywhere that can keep an OCI container running with outbound Internet access. No inbound terminal port is required; port `8080` is only for platform health checks.

## Build and publish a multi-architecture image

Authenticate Docker to your registry, then run:

```sh
./build-and-push.sh ghcr.io/YOUR_ORG/attached-herdr:0.8.2-0.2.3
```

The helper requests BuildKit provenance and an SBOM and publishes `linux/amd64` plus `linux/arm64`. Replace the image placeholder in downstream manifests with the immutable digest emitted by your registry for production use.

## Kubernetes

Create a Secret without putting its values in YAML:

```sh
kubectl create secret generic attached-herdr \
  --from-file=publish-bundle=/secure/path/publish.bundle \
  --from-file=local-password=/secure/path/local-password
```

Replace the fail-closed `ghcr.io/REPLACE_ME/...@sha256:000...` value in `kubernetes.yaml` with the immutable manifest digest reported by your registry, then apply it:

```sh
kubectl apply -f kubernetes.yaml
kubectl rollout status deployment/attached-herdr
kubectl logs -f deployment/attached-herdr
```

The Deployment uses `Recreate`, one replica, an unprivileged user, dropped capabilities, a read-only root filesystem, no mounted Kubernetes service-account token, startup-gated health probes, and `fsGroup`-writable `emptyDir` storage. Deleting or replacing the Pod destroys the Herdr session. Change `home` and `workspace` to PVCs if that is not desired.

Stop it with `kubectl delete deployment attached-herdr`; remove the Secret separately when it is no longer needed.

## GitHub Actions runner

Copy `github-actions.yml` to `.github/workflows/attached-herdr.yml` in a repository containing this `recipes/docker` context. Create a protected GitHub Environment named `attached-herdr`, restrict its deployment branches, require reviewers, and add environment secrets named:

- `ATTACHED_PUBLISH_BUNDLE`
- `ATTACHED_LOCAL_PASSWORD`

Run **Ephemeral Attached Herdr session** manually from a trusted revision and choose a lifetime. The workflow copies the GitHub secrets into root-owned mode-`0600` temporary files, unsets their exported values before invoking Docker, and removes the files during cleanup. The entrypoint starts as root only to read those mounts, then drops permanently to the unprivileged runner UID. The checkout is mounted read/write at `/workspace`, and a temporary home is mounted separately so coding panes can edit the checkout without running as root. The host label is unique to the workflow run.

The checked-out Docker context receives the secrets at runtime and could exfiltrate them if modified maliciously. Never approve an untrusted branch or pull-request revision. The job is intentionally billable and capped below the hosted runner's timeout; cancel it or use Attached and then stop it early when finished. Runner cancellation destroys all panes and files.

## Fly Machines, Railway, Render, ECS/Fargate, Nomad, and VM sandboxes

Use the same image and map the platform controls as follows:

1. Inject `ATTACHED_PUBLISH_BUNDLE` and `ATTACHED_LOCAL_PASSWORD` from the platform secret store.
2. Set a unique, stable `ATTACHED_HOST_LABEL` using only letters, digits, `.`, `_`, and `-` (maximum 64 bytes).
3. Route the platform's HTTP health check to port `8080`, path `/healthz`.
4. Allow outbound TCP/UDP and HTTPS; do not expose a shell port.
5. Run as UID/GID `10001`, drop Linux capabilities, disable privilege escalation, and make the root filesystem read-only where the platform supports those controls.
6. Give the container at least 512 MiB RAM, increasing CPU/RAM for coding agents and builds.
7. Use a persistent volume at `/home/herdr` and `/workspace` only when file persistence is intentional.
8. Send `SIGTERM` with at least a 20-second grace period and disable scale-to-zero while someone is attached.

If a platform suspends processes rather than replacing the instance, Attached will reconnect after resume. If it replaces the instance, the old Herdr session is gone and the new publisher starts a fresh `default` session.

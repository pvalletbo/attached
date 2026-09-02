# Docker: headless Herdr published by Attached

> **AI contribution notice:** This recipe document was created with assistance from an AI coding agent and is intended for human review.

This image is the portable base for the other recipes. Its long-lived Attached and Herdr processes run as UID/GID `10001`; it serves only a minimal health endpoint on port `8080` and needs outbound HTTPS/QUIC connectivity for Attached and Iroh. Compose publishes the health port on host loopback only.

## Docker Compose

From this directory:

```sh
cp .env.example .env
mkdir -p secrets
cp /secure/path/publish.bundle secrets/publish.bundle
cp /secure/path/local-password secrets/local-password
chmod 600 secrets/publish.bundle secrets/local-password

docker compose build
docker compose up -d
docker compose logs -f herdr
```

The `.env` file contains paths and the non-secret host label; Compose mounts the values as Docker secrets. Do not put bundle or password contents in `.env`. Compose initially runs the entrypoint as root so it can read mode-`0600` bind-mounted secret files. The entrypoint immediately copies them into a private temporary directory and irreversibly drops to UID/GID `10001` before starting Attached or Herdr; only the capabilities needed for that staging and privilege drop are granted.

After the log reports `Serving synchronized Herdr sessions`, attach from a workstation configured with the matching download bundle:

```sh
attached sessions list
attached attach docker-herdr/default
```

Stop and remove the publisher with:

```sh
docker compose down
```

The named `herdr-home` and `herdr-workspace` volumes preserve workspace files and on-disk metadata across ordinary container recreation. Recreation still terminates all live pane processes and PTYs; volumes are not process checkpoints. Delete the volumes when their retained files are no longer needed.

## Plain Docker

Build once:

```sh
docker build -t attached-herdr:0.8.2-0.2.3 .
```

Prefer file mounts so secrets never enter the initial process environment:

```sh
docker run --rm --name attached-herdr \
  --stop-timeout 20 \
  --user 0:0 \
  --cap-drop ALL \
  --cap-add CHOWN --cap-add DAC_OVERRIDE --cap-add SETGID --cap-add SETUID \
  --security-opt no-new-privileges \
  --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,mode=1777 \
  --mount type=bind,src="$PWD/secrets/publish.bundle",dst=/run/secrets/publish.bundle,readonly \
  --mount type=bind,src="$PWD/secrets/local-password",dst=/run/secrets/local-password,readonly \
  --mount type=volume,src=herdr-home,dst=/home/herdr \
  --mount type=volume,src=herdr-workspace,dst=/workspace \
  -e ATTACHED_PUBLISH_BUNDLE_FILE=/run/secrets/publish.bundle \
  -e ATTACHED_LOCAL_PASSWORD_FILE=/run/secrets/local-password \
  -e ATTACHED_HOST_LABEL=docker-herdr \
  -p 127.0.0.1:8080:8080 \
  attached-herdr:0.8.2-0.2.3
```

The `--user 0:0` override is needed only to read host-owned mode-`0600` secret mounts; the image's configured `ATTACHED_RUN_AS_UID` and `ATTACHED_RUN_AS_GID` make the entrypoint drop privileges before it launches the publisher.

`GET http://127.0.0.1:8080/healthz` is only a platform health check. It does not expose a terminal; remote attachment still requires the download credential.

## Customize the coding environment

Extend the image to install the agent CLIs and build tools your panes need:

```dockerfile
FROM attached-herdr:0.8.2-0.2.3
USER root
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
USER herdr
```

Pass model/API credentials at runtime through the target platform's secret store. Never add them with Docker `ARG`, `ENV`, or `COPY`.

## Inputs

| Variable | Required | Purpose |
| --- | --- | --- |
| `ATTACHED_PUBLISH_BUNDLE_FILE` or `ATTACHED_PUBLISH_BUNDLE` | Yes | Publish-only Attached bundle |
| `ATTACHED_LOCAL_PASSWORD_FILE` or `ATTACHED_LOCAL_PASSWORD` | Yes | Stable password for local Attached encryption |
| `ATTACHED_HOST_LABEL` | Recommended | Catalog host label; defaults to Attached's endpoint-derived label |
| `ATTACHED_HEALTH_PORT` | No | Health port, default `8080`; use `0` to disable |
| `ATTACHED_STARTUP_TIMEOUT_SECONDS` | No | Publication timeout from `1` to `900` seconds; default `120` |
| `ATTACHED_STATE_DIR` | No | Attached state, default `/home/herdr/.local/state/attached` |
| `HERDR_STARTUP_CWD` | No | Initial workspace, default `/workspace` |

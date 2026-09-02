# syntax=docker/dockerfile:1.7.0@sha256:dbbd5e059e8a07ff7ea6233b213b36aa516b4c53c645f1817a4dd18b83cbea56
FROM docker.io/library/debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

LABEL org.opencontainers.image.title="Attached Herdr session host" \
      org.opencontainers.image.description="Headless Herdr published securely through Attached" \
      org.opencontainers.image.source="https://github.com/pvalletbo/attached" \
      dev.herdr.version="0.8.2" \
      sh.attached.version="0.2.3"

ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        busybox \
        ca-certificates \
        curl \
        expect \
        git \
        openssh-client \
        passwd \
        procps \
        tini \
        util-linux \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

COPY --chmod=0755 install-runtime.sh /tmp/install-runtime.sh
RUN TARGETARCH="$TARGETARCH" /tmp/install-runtime.sh \
    && rm -f /tmp/install-runtime.sh

COPY --chmod=0755 entrypoint.sh /usr/local/bin/attached-herdr-entrypoint
COPY --chmod=0755 run-attached.exp /usr/local/libexec/attached-herdr/run-attached.exp

RUN useradd --create-home --uid 10001 --shell /bin/bash herdr \
    && install -d -o herdr -g herdr -m 0700 /workspace /home/herdr/.local/state

USER herdr
WORKDIR /workspace
ENV HOME=/home/herdr \
    LANG=C.UTF-8 \
    SHELL=/bin/bash \
    TERM=xterm-256color \
    HERDR_STARTUP_CWD=/workspace \
    ATTACHED_STATE_DIR=/home/herdr/.local/state/attached \
    ATTACHED_HEALTH_PORT=8080 \
    ATTACHED_RUN_AS_UID=10001 \
    ATTACHED_RUN_AS_GID=10001 \
    ATTACHED_INIT_BIN=/usr/bin/tini

EXPOSE 8080
VOLUME ["/home/herdr", "/workspace"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/attached-herdr-entrypoint"]

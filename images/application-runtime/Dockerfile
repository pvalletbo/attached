# syntax=docker/dockerfile:1.7.0@sha256:dbbd5e059e8a07ff7ea6233b213b36aa516b4c53c645f1817a4dd18b83cbea56
FROM docker.io/library/debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

ARG TARGETARCH

LABEL org.opencontainers.image.title="Attached application runtime" \
      org.opencontainers.image.description="Application runtime layer containing Attached and Herdr" \
      org.opencontainers.image.source="https://github.com/pvalletbo/attached" \
      dev.herdr.version="0.8.2" \
      sh.attached.version="0.2.9"

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        git \
        less \
        libgcc-s1 \
        procps \
        xz-utils \
    && rm -rf /var/lib/apt/lists/*

COPY --chmod=0755 install-runtime.sh /tmp/install-runtime.sh
RUN TARGETARCH="${TARGETARCH}" /tmp/install-runtime.sh \
    && rm -f /tmp/install-runtime.sh \
    && attached --version \
    && herdr --version

ENV SHELL=/bin/bash \
    TERM=xterm-256color

CMD ["/bin/bash"]

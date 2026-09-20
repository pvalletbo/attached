# Rust harness and real CLI, built from the checkout. No credentials in images.
FROM rust:1.97.1-bookworm AS harness-build
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
ENV CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0
RUN cargo build --locked --jobs 1 --package attached-e2e
# Exercise the Linux PTY adapter offline before any real account is created.
RUN cargo test --locked --offline --jobs 1 --package attached-e2e

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates openssh-client util-linux tar xz-utils \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 --shell /bin/sh attached
COPY --from=harness-build /build/target/debug/attached-e2e /usr/local/bin/attached-e2e
ENV HOME=/home/attached
WORKDIR /home/attached
USER attached
CMD ["sleep", "600"]

# Keep this target before CLI compilation for legacy Docker builders as well.
FROM runtime AS release
USER root
ARG ATTACHED_VERSION
RUN if [ -n "$ATTACHED_VERSION" ]; then attached-e2e __install-release "$ATTACHED_VERSION"; fi
USER attached

FROM harness-build AS cli-build
RUN cargo build --locked --jobs 1 --package attached

FROM runtime AS source
COPY --from=cli-build /build/target/debug/attached /usr/local/bin/attached

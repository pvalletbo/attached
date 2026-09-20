# Build the checkout: --target source. Test a release: --target release
# --build-arg ATTACHED_VERSION=0.3.5. Neither image contains account credentials.
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates openssh-client python3 python3-pexpect \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 --shell /bin/sh attached
COPY e2e/*.py /opt/e2e/
ENV HOME=/home/attached PYTHONDONTWRITEBYTECODE=1
WORKDIR /home/attached
USER attached
CMD ["sleep", "600"]

# This target precedes the compiler so release tests also work with the legacy
# Docker builder without compiling Rust or downloading a Rust toolchain.
FROM runtime AS release
USER root
ARG ATTACHED_VERSION
RUN if [ -n "$ATTACHED_VERSION" ]; then \
        python3 /opt/e2e/install_release.py "$ATTACHED_VERSION"; fi
USER attached

FROM rust:1.97.1-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
# Keep compilation viable on small Docker VMs; this is the real CLI, not a
# cfg(test) binary. Release mode is exercised separately with --release.
ENV CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0
RUN cargo build --locked --jobs 1 --package attached

FROM runtime AS source
COPY --from=build /build/target/debug/attached /usr/local/bin/attached

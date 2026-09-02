#!/bin/sh
set -eu

HERDR_VERSION="0.8.2"
ATTACHED_VERSION="0.2.3"
DESTDIR="${DESTDIR:-/usr/local/bin}"
TARGETARCH="${TARGETARCH:-}"

if [ -z "$TARGETARCH" ]; then
    case "$(uname -m)" in
        x86_64) TARGETARCH="amd64" ;;
        aarch64 | arm64) TARGETARCH="arm64" ;;
        *)
            printf 'unsupported build architecture: %s\n' "$(uname -m)" >&2
            exit 1
            ;;
    esac
fi

case "$TARGETARCH" in
    amd64)
        herdr_asset="herdr-linux-x86_64"
        herdr_sha256="976150a14d490c94b243ea2e1a7eb2dfb67f12e36b182db90936f6728e6aecf4"
        attached_target="x86_64-unknown-linux-gnu"
        attached_sha256="d20cabdcb4e3b8e6d7b3119d0d8af9f6032cd73a78c887f4fc7e1392d9dea16c"
        ;;
    arm64)
        herdr_asset="herdr-linux-aarch64"
        herdr_sha256="f55610658e1c2e0d2aaef730b4b2ab885f7f8ba00285ab372bfb14f2e3d5b40d"
        attached_target="aarch64-unknown-linux-gnu"
        attached_sha256="fee75516eb03947960e695264b51404a453ecbccaffbf3821b907588ef600956"
        ;;
    *)
        printf 'unsupported Docker TARGETARCH: %s\n' "$TARGETARCH" >&2
        exit 1
        ;;
esac

workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT HUP INT TERM

herdr_url="https://github.com/herdrdev/herdr/releases/download/v${HERDR_VERSION}/${herdr_asset}"
attached_archive="attached-${attached_target}.tar.xz"
attached_url="https://github.com/pvalletbo/attached/releases/download/v${ATTACHED_VERSION}/${attached_archive}"

curl --proto '=https' --tlsv1.2 --fail --show-error --silent --location \
    --retry 3 --retry-all-errors --max-filesize 67108864 \
    --output "$workdir/herdr" "$herdr_url"
printf '%s  %s\n' "$herdr_sha256" "$workdir/herdr" | sha256sum -c - >/dev/null

curl --proto '=https' --tlsv1.2 --fail --show-error --silent --location \
    --retry 3 --retry-all-errors --max-filesize 67108864 \
    --output "$workdir/$attached_archive" "$attached_url"
printf '%s  %s\n' "$attached_sha256" "$workdir/$attached_archive" | sha256sum -c - >/dev/null

tar --extract --xz --file "$workdir/$attached_archive" --directory "$workdir"

mkdir -p "$DESTDIR"
install -m 0755 "$workdir/herdr" "$DESTDIR/herdr"
install -m 0755 \
    "$workdir/attached-${attached_target}/attached" \
    "$DESTDIR/attached"

printf 'installed Herdr %s and Attached %s for %s\n' \
    "$HERDR_VERSION" "$ATTACHED_VERSION" "$TARGETARCH"

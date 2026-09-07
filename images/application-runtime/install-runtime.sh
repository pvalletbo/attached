#!/bin/sh
set -eu

ATTACHED_VERSION=0.2.9
HERDR_VERSION=0.8.2
DESTDIR=/usr/local/bin

case "${TARGETARCH:-}" in
    amd64)
        attached_target=x86_64-unknown-linux-gnu
        attached_sha256=436bf249df524ddcb3cb2714cf6f525e160a03dfee49d0363e971dc99b0d42f2
        herdr_asset=herdr-linux-x86_64
        herdr_sha256=976150a14d490c94b243ea2e1a7eb2dfb67f12e36b182db90936f6728e6aecf4
        ;;
    arm64)
        attached_target=aarch64-unknown-linux-gnu
        attached_sha256=ad2200ab4c8119fbef6d0f4203c71d3aa86ff7bcfa59f8f28636f275d014a2ca
        herdr_asset=herdr-linux-aarch64
        herdr_sha256=f55610658e1c2e0d2aaef730b4b2ab885f7f8ba00285ab372bfb14f2e3d5b40d
        ;;
    *)
        printf 'unsupported target architecture: %s\n' "${TARGETARCH:-unset}" >&2
        exit 1
        ;;
esac

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT HUP INT TERM

attached_archive="attached-${attached_target}.tar.xz"
curl --fail --location --silent --show-error --retry 3 \
    --output "${workdir}/${attached_archive}" \
    "https://github.com/pvalletbo/attached/releases/download/v${ATTACHED_VERSION}/${attached_archive}"
printf '%s  %s\n' "${attached_sha256}" "${workdir}/${attached_archive}" | sha256sum --check --strict -
tar --extract --xz --file "${workdir}/${attached_archive}" --directory "${workdir}"

curl --fail --location --silent --show-error --retry 3 \
    --output "${workdir}/${herdr_asset}" \
    "https://github.com/herdrdev/herdr/releases/download/v${HERDR_VERSION}/${herdr_asset}"
printf '%s  %s\n' "${herdr_sha256}" "${workdir}/${herdr_asset}" | sha256sum --check --strict -

install --mode 0755 "${workdir}/attached-${attached_target}/attached" "${DESTDIR}/attached"
install --mode 0755 "${workdir}/${herdr_asset}" "${DESTDIR}/herdr"

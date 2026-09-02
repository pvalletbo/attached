#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    printf 'usage: %s REGISTRY/IMAGE:TAG\n' "$0" >&2
    exit 2
fi

image="$1"
script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
docker_dir="$(dirname -- "$script_dir")/docker"

docker buildx build \
    --platform linux/amd64,linux/arm64 \
    --provenance=true \
    --sbom=true \
    --push \
    --tag "$image" \
    "$docker_dir"

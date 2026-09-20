#!/usr/bin/env bash
# Build the consumer only: no CLI, subprocesses, clipboard or desktop state store.
set -euo pipefail

if [[ "${1:-}" == --help ]]; then
  cat <<'HELP'
Usage: scripts/build-apple-client.sh [output-package-directory]
Requires macOS, full Xcode (xcode-select), Rust 1.97.1 and its Apple targets.
Builds a local AttachedMobile Swift package with device, universal simulator,
and host-macOS slices. Run from an Attached checkout at the desired commit.
The default destination is target/AttachedMobile. No signing is required.
HELP
  exit 0
fi
[[ "$(uname -s)" == Darwin ]] || { echo 'Apple SDKs require macOS and Xcode.' >&2; exit 1; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT="${1:-$ROOT/target/AttachedMobile}"
mkdir -p "$OUTPUT"
OUTPUT="$(cd "$OUTPUT" && pwd)"
cd "$ROOT"
command -v cargo >/dev/null
command -v rustup >/dev/null
xcrun --find clang >/dev/null

# Keep output paths independent of a caller's Cargo environment.
export CARGO_TARGET_DIR="$ROOT/target/apple-client"
HOST_TARGET="$(rustc -vV | sed -n 's/^host: //p')"
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
cargo build --locked --release -p attached-mobile --features bindgen
GENERATED="$CARGO_TARGET_DIR/generated"
mkdir -p "$GENERATED"
"$CARGO_TARGET_DIR/release/attached-bindgen" generate \
  --library "$CARGO_TARGET_DIR/release/libattached_mobile.dylib" \
  --language swift --config crates/mobile/uniffi.toml --out-dir "$GENERATED"

for TARGET in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
  SDK=iphonesimulator
  [[ "$TARGET" == aarch64-apple-ios ]] && SDK=iphoneos
  SDKROOT="$(xcrun --sdk "$SDK" --show-sdk-path)" \
    IPHONEOS_DEPLOYMENT_TARGET=18.0 \
    cargo build --locked --release -p attached-mobile --lib --target "$TARGET"
done

HEADERS="$CARGO_TARGET_DIR/headers"
mkdir -p "$HEADERS" "$CARGO_TARGET_DIR/universal-simulator"
cp "$GENERATED/AttachedMobileFFI.h" "$HEADERS/"
cp "$GENERATED/AttachedMobileFFI.modulemap" "$HEADERS/module.modulemap"
xcrun lipo -create \
  "$CARGO_TARGET_DIR/aarch64-apple-ios-sim/release/libattached_mobile.a" \
  "$CARGO_TARGET_DIR/x86_64-apple-ios/release/libattached_mobile.a" \
  -output "$CARGO_TARGET_DIR/universal-simulator/libattached_mobile.a"

# xcodebuild refuses to replace an existing framework. Remove only our named
# generated artifact, never the caller's output directory or source checkout.
mkdir -p "$OUTPUT/Artifacts" "$OUTPUT/Sources/AttachedMobile"
rm -rf "$OUTPUT/Artifacts/AttachedMobileFFI.xcframework"
xcodebuild -create-xcframework \
  -library "$CARGO_TARGET_DIR/aarch64-apple-ios/release/libattached_mobile.a" -headers "$HEADERS" \
  -library "$CARGO_TARGET_DIR/universal-simulator/libattached_mobile.a" -headers "$HEADERS" \
  -library "$CARGO_TARGET_DIR/release/libattached_mobile.a" -headers "$HEADERS" \
  -output "$OUTPUT/Artifacts/AttachedMobileFFI.xcframework"
cp "$ROOT/bindings/apple/Package.swift" "$OUTPUT/Package.swift"
cp "$GENERATED/AttachedMobile.swift" "$OUTPUT/Sources/AttachedMobile/"
echo "Built AttachedMobile package at $OUTPUT (macOS slice: $HOST_TARGET)"

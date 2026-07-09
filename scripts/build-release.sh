#!/usr/bin/env bash
#
# Build release `neo` binaries for the initially-supported targets:
#   - macOS   (native host arch: aarch64 or x86_64)
#   - Ubuntu/Linux x86_64 (via a Docker builder, so it works from macOS)
#
# Output: dist/neo-<target>[.tar.gz]
#
# Usage:
#   scripts/build-release.sh                # both targets (Linux needs Docker)
#   scripts/build-release.sh macos          # macOS only
#   scripts/build-release.sh linux          # Linux x86_64 only
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST="$ROOT/dist"
WHAT="${1:-all}"
mkdir -p "$DIST"

build_macos() {
  local arch target
  arch="$(uname -m)"
  case "$arch" in
    arm64|aarch64) target="aarch64-apple-darwin" ;;
    x86_64)        target="x86_64-apple-darwin" ;;
    *) echo "unsupported macOS arch: $arch" >&2; return 1 ;;
  esac
  echo ">> building macOS ($target)"
  rustup target add "$target" >/dev/null 2>&1 || true
  ( cd "$ROOT" && cargo build --release -p neo-cli --target "$target" )
  local out="$DIST/neo-$target"
  cp "$ROOT/target/$target/release/neo" "$out"
  echo "   -> $out"
  ( cd "$DIST" && tar czf "neo-$target.tar.gz" "neo-$target" )
  echo "   -> $DIST/neo-$target.tar.gz"
}

build_linux() {
  local target="x86_64-unknown-linux-gnu"
  echo ">> building Linux ($target) via Docker"
  if ! docker info >/dev/null 2>&1; then
    echo "   Docker is not running — start Docker Desktop and retry, or build" >&2
    echo "   this target on an Ubuntu host with: cargo build --release -p neo-cli" >&2
    return 1
  fi
  # rust:1-bookworm is glibc-based; the resulting binary runs on Ubuntu 22.04+.
  # reqwest uses rustls (no OpenSSL), so there is no system TLS dependency.
  docker run --rm -v "$ROOT":/src -w /src rust:1-bookworm \
    bash -c "rustup target add $target >/dev/null 2>&1 || true; cargo build --release -p neo-cli --target $target"
  local out="$DIST/neo-$target"
  cp "$ROOT/target/$target/release/neo" "$out"
  echo "   -> $out"
  ( cd "$DIST" && tar czf "neo-$target.tar.gz" "neo-$target" )
  echo "   -> $DIST/neo-$target.tar.gz"
}

case "$WHAT" in
  macos) build_macos ;;
  linux) build_linux ;;
  all)   build_macos; build_linux || echo "!! Linux build skipped/failed (see above)";;
  *) echo "usage: $0 [all|macos|linux]" >&2; exit 2 ;;
esac

echo
echo "artifacts in $DIST:"
ls -la "$DIST" | sed 's/^/   /'

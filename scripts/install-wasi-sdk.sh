#!/usr/bin/env bash
# Download and install wasi-sdk into .wasi-sdk/ at the repo root.
#
# Usage:
#     scripts/install-wasi-sdk.sh           # installs pinned version
#     WASI_SDK_VERSION=33 scripts/install-wasi-sdk.sh
#     WASI_SDK_DEST=/opt/wasi-sdk scripts/install-wasi-sdk.sh

set -euo pipefail

VERSION="${WASI_SDK_VERSION:-33}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST="${WASI_SDK_DEST:-$REPO_ROOT/.wasi-sdk}"

case "$(uname -s)" in
    Darwin) os=macos ;;
    Linux)  os=linux ;;
    *) echo "unsupported OS: $(uname -s)" >&2; exit 1 ;;
esac

case "$(uname -m)" in
    x86_64|amd64) arch=x86_64 ;;
    arm64|aarch64) arch=arm64 ;;
    *) echo "unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac

tarball="wasi-sdk-${VERSION}.0-${arch}-${os}.tar.gz"
url="https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${VERSION}/${tarball}"

if [ -x "$DEST/bin/clang" ]; then
    existing=$(cat "$DEST/VERSION" 2>/dev/null | head -1 || echo unknown)
    echo "wasi-sdk already installed at $DEST (version $existing)"
    echo "remove $DEST to force reinstall"
    exit 0
fi

mkdir -p "$DEST"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "downloading $url"
curl --fail --location --progress-bar "$url" -o "$tmp/sdk.tar.gz"

echo "extracting to $DEST"
tar -xzf "$tmp/sdk.tar.gz" -C "$tmp"

inner=$(find "$tmp" -maxdepth 1 -type d -name "wasi-sdk-*" | head -1)
if [ -z "$inner" ]; then
    echo "unexpected archive layout" >&2
    exit 1
fi

# Move contents (not the wrapper dir) into DEST so $DEST/bin/clang works.
shopt -s dotglob
mv "$inner"/* "$DEST"/
shopt -u dotglob

if [ ! -x "$DEST/bin/clang" ]; then
    echo "install failed: $DEST/bin/clang not executable" >&2
    exit 1
fi

echo
echo "installed wasi-sdk $(cat "$DEST/VERSION" | head -1) to $DEST"
echo "the Makefile will pick this up automatically; to use explicitly:"
echo "    export WASI_SDK=$DEST"

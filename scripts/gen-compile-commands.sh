#!/usr/bin/env bash
# Generate compile_commands.json for clangd so it can resolve
# bindings/openssl.h, wasi-sdk sysroot headers, etc.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WASI_SDK="${WASI_SDK:-$ROOT/.wasi-sdk}"
SYSROOT="$WASI_SDK/share/wasi-sysroot"
TARGET="wasm32-wasip2"
CLANG="$WASI_SDK/bin/clang"

CFLAGS=(
  --target="$TARGET" --sysroot="$SYSROOT"
  -O2 -fno-strict-aliasing -Wall -Wextra -Wno-unused-parameter
  -D_WASI_EMULATED_MMAN -D_WASI_EMULATED_SIGNAL
  -D_WASI_EMULATED_PROCESS_CLOCKS -D_WASI_EMULATED_GETPID
  -I"$ROOT/third_party/openssl/include"
  -I"$ROOT/build/openssl/include"
  -Isrc -I"$ROOT/src/bindings" -I"$ROOT/src/include"
)

{
  echo "["
  first=1
  for f in "$ROOT"/src/*.c; do
    [ "$first" -eq 1 ] && first=0 || echo "  ,"
    echo "  {"
    echo "    \"directory\": \"$ROOT\","
    echo "    \"file\": \"$f\","
    echo -n "    \"arguments\": [\"$CLANG\""
    for a in "${CFLAGS[@]}"; do printf ', "%s"' "$a"; done
    echo ", \"-c\", \"$f\"]"
    echo "  }"
  done
  echo "]"
} > "$ROOT/compile_commands.json"

echo "wrote $ROOT/compile_commands.json"

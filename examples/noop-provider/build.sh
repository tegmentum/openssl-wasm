#!/usr/bin/env bash
# Build the noop-provider component.
# Uses the same wasi-sdk clang openssl-wasm uses.

set -euo pipefail
cd "$(dirname "$0")"

CLANG="${CLANG:-../../.wasi-sdk/bin/clang}"
SYSROOT="${SYSROOT:-../../.wasi-sdk/share/wasi-sysroot}"
OUT=build
mkdir -p "$OUT"

# Regenerate bindings if WIT changed.
if [ wit/world.wit -nt "$OUT/.bindings-stamp" ] \
   || [ ! -f src/noop.c ]; then
  wit-bindgen c --world noop --out-dir src wit
  touch "$OUT/.bindings-stamp"
fi

CFLAGS=(
  --target=wasm32-wasip2
  --sysroot="$SYSROOT"
  -O2 -fno-strict-aliasing
  -Wall -Wextra -Wno-unused-parameter
  -Isrc
)

"$CLANG" "${CFLAGS[@]}" -c src/noop.c       -o "$OUT/noop.o"
"$CLANG" "${CFLAGS[@]}" -c src/noop_impl.c  -o "$OUT/noop_impl.o"

"$CLANG" --target=wasm32-wasip2 --sysroot="$SYSROOT" \
  -mexec-model=reactor -Wl,--no-entry -Wl,--export-dynamic \
  "$OUT/noop.o" "$OUT/noop_impl.o" src/noop_component_type.o \
  -o "$OUT/noop-provider.wasm"

wasm-tools validate "$OUT/noop-provider.wasm"
echo "built: $OUT/noop-provider.wasm ($(stat -f%z "$OUT/noop-provider.wasm" 2>/dev/null || stat -c%s "$OUT/noop-provider.wasm") bytes)"

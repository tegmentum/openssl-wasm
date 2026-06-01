#!/usr/bin/env bash
# Build the wit-bridge stub stack for the wit_bridge.rs smoke tests.
# Produces /tmp/full-stack.wasm; export OPENSSL_WASM_COMPONENT to it
# before `cargo test --test wit_bridge`.
#
# Requires that the sibling crates have been built once:
#   cd ~/git/stub-key-backend          && cargo build --release --target wasm32-wasip2
#   cd ~/git/simple-provider-adapter   && cargo build --release --target wasm32-wasip2
#   cd ~/git/openssl-wasm/examples/noop-provider && bash build.sh
#   cd ~/git/openssl-wasm              && make component

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
SIBLING_ROOT="${SIBLING_ROOT:-$HOME/git}"
OUT="${OUT:-/tmp/full-stack.wasm}"

STUB="$SIBLING_ROOT/stub-key-backend/target/wasm32-wasip2/release/stub_key_backend.wasm"
SIMPLE="$SIBLING_ROOT/simple-provider-adapter/target/wasm32-wasip2/release/simple_provider_adapter.wasm"
NOOP="$REPO_ROOT/examples/noop-provider/build/noop-provider.wasm"
CORE="$REPO_ROOT/build/openssl-component.wasm"

for f in "$STUB" "$SIMPLE" "$NOOP" "$CORE"; do
  [ -r "$f" ] || { echo "missing artifact: $f" >&2; exit 1; }
done

wac compose "$HERE/wit_bridge_stub_compose.wac" \
  --dep "stub-key-backend:component=$STUB" \
  --dep "simple-provider-adapter:component=$SIMPLE" \
  --dep "noop-provider:component=$NOOP" \
  --dep "openssl-wasm:component=$CORE" \
  -o "$OUT"
wasm-tools validate "$OUT"
echo "built: $OUT"

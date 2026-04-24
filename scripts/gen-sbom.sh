#!/usr/bin/env bash
# Emit a CycloneDX 1.5 SBOM for the component, listing:
# - the component itself (repo + commit)
# - OpenSSL (version from submodule tag)
# - wasi-sdk version
# - wasi-libc revision
# - clang version
# Does NOT cover the Rust host dependencies — those are visible in
# examples/host/Cargo.lock separately.
#
# Writes to build/openssl-component.sbom.json. Invoke as `make sbom`.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WASI_SDK="${WASI_SDK:-$ROOT/.wasi-sdk}"

component_path="$ROOT/build/openssl-component.wasm"
out="$ROOT/build/openssl-component.sbom.json"

if [ ! -f "$component_path" ]; then
  echo "error: component not built; run \`make\` first" >&2
  exit 1
fi

repo_commit=$(git -C "$ROOT" rev-parse HEAD)
repo_describe=$(git -C "$ROOT" describe --always --dirty --tags 2>/dev/null || echo "$repo_commit")

ossl_tag=$(git -C "$ROOT/third_party/openssl" describe --tags --exact-match 2>/dev/null || \
            git -C "$ROOT/third_party/openssl" rev-parse HEAD)
ossl_commit=$(git -C "$ROOT/third_party/openssl" rev-parse HEAD)
ossl_version=$(echo "$ossl_tag" | sed 's/^openssl-//')

wasi_sdk_version=$(head -1 "$WASI_SDK/VERSION" 2>/dev/null || echo unknown)
wasi_libc_rev=$(grep -E '^wasi-libc:' "$WASI_SDK/VERSION" 2>/dev/null | awk '{print $2}' || echo unknown)
clang_version=$("$WASI_SDK/bin/clang" --version 2>/dev/null | head -1 || echo unknown)

component_sha256=$(shasum -a 256 "$component_path" | awk '{print $1}')
component_size=$(wc -c < "$component_path" | tr -d ' ')
serial_num=$(openssl rand -hex 16 2>/dev/null || echo "$(date +%s)$$")
iso_now=$(date -u +%Y-%m-%dT%H:%M:%SZ)

cat > "$out" <<EOF
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:${serial_num}",
  "version": 1,
  "metadata": {
    "timestamp": "${iso_now}",
    "tools": [
      {"name": "gen-sbom.sh", "version": "${repo_describe}"}
    ],
    "component": {
      "type": "library",
      "bom-ref": "openssl-wasm@${repo_describe}",
      "name": "openssl-wasm",
      "version": "${repo_describe}",
      "description": "OpenSSL compiled as a wasm32-wasip2 component",
      "hashes": [
        {"alg": "SHA-256", "content": "${component_sha256}"}
      ],
      "properties": [
        {"name": "artifact_bytes", "value": "${component_size}"},
        {"name": "git_commit",     "value": "${repo_commit}"}
      ]
    }
  },
  "components": [
    {
      "type": "library",
      "bom-ref": "pkg:generic/openssl@${ossl_version}",
      "name": "openssl",
      "version": "${ossl_version}",
      "description": "Upstream OpenSSL, built statically into the component",
      "licenses": [{"license": {"id": "Apache-2.0"}}],
      "externalReferences": [
        {"type": "vcs", "url": "https://github.com/openssl/openssl"}
      ],
      "properties": [
        {"name": "git_commit", "value": "${ossl_commit}"}
      ]
    },
    {
      "type": "library",
      "bom-ref": "wasi-sdk@${wasi_sdk_version}",
      "name": "wasi-sdk",
      "version": "${wasi_sdk_version}",
      "description": "WASI SDK toolchain used to build the component",
      "externalReferences": [
        {"type": "vcs", "url": "https://github.com/WebAssembly/wasi-sdk"}
      ],
      "properties": [
        {"name": "wasi_libc_rev",  "value": "${wasi_libc_rev}"},
        {"name": "clang_version",  "value": "${clang_version}"}
      ]
    }
  ]
}
EOF

echo "wrote $out (component: $component_sha256)"

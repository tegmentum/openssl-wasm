#!/usr/bin/env bash
# Fetch Mozilla's current CA trust list (as curated and published by the
# curl project) into examples/host/fixtures/cacert.pem. Avoids reliance
# on the host system's /etc/ssl, which differs by OS and version.
#
# The URL is curl's canonical location; they publish updates ~quarterly.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT/examples/host/fixtures"
OUT="$OUT_DIR/cacert.pem"

URL="${CA_BUNDLE_URL:-https://curl.se/ca/cacert.pem}"

# Pin the SHA-256 of the bundle we've tested with. Update this when
# you refresh the bundle.
EXPECTED_SHA256="${CA_BUNDLE_SHA256:-}"

mkdir -p "$OUT_DIR"
echo "fetching $URL"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
curl --fail --location --silent --show-error "$URL" -o "$tmp"

got_sha=$(shasum -a 256 "$tmp" | awk '{print $1}')
if [ -n "$EXPECTED_SHA256" ]; then
    if [ "$got_sha" != "$EXPECTED_SHA256" ]; then
        echo "checksum mismatch:" >&2
        echo "  expected: $EXPECTED_SHA256" >&2
        echo "  got:      $got_sha" >&2
        echo "If this is an intentional update, export CA_BUNDLE_SHA256=$got_sha" >&2
        exit 1
    fi
fi

mv "$tmp" "$OUT"
trap - EXIT
echo "wrote $OUT"
echo "sha256: $got_sha"
echo "count:  $(grep -c 'BEGIN CERTIFICATE' "$OUT") certificates"

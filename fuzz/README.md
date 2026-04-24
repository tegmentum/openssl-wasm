# openssl-wasm-fuzz

libFuzzer harnesses for the component's parse paths — the
attacker-controlled DER/PEM inputs that have historically been a rich
source of CVEs in X.509 stacks.

## Prerequisites

```sh
cargo install cargo-fuzz     # uses libFuzzer; nightly recommended
```

## Running

From the repo root, first build the component so the harness can load it:

```sh
make component
export OPENSSL_WASM_COMPONENT=$PWD/build/openssl-component.wasm
```

Then run a target. `cert_parse` is the most valuable:

```sh
cd fuzz
cargo +nightly fuzz run cert_parse -- -runs=100000
```

Or leave it running:

```sh
cargo +nightly fuzz run cert_parse
```

The corpus is persisted under `fuzz/corpus/cert_parse/`. Crashes land
in `fuzz/artifacts/cert_parse/`.

## Targets

- `cert_parse`: certificate.parse with DER and PEM encodings
- `csr_parse`: csr.parse
- `crl_parse`: crl.parse
- `pkey_load_private`: pkey.load-private across all format × encoding combos
- `cms_verify`: cms_verify with a persistent store handle

## Why this matters

The component's parse paths go through OpenSSL's ASN.1 decoder, which
has a long history of CVEs. wasm sandboxing converts most memory
bugs into traps (which libFuzzer catches as crashes) rather than RCE,
but it doesn't make the bugs acceptable. A crash is still a DoS on
anyone loading attacker-controlled certs, and an unbounded-allocation
bug could be used for memory exhaustion.

## Performance

Each iteration:
- Locks a process-global Mutex (trivial)
- Calls into wasmtime (submillisecond once warm)
- Clears the component's error queue

Expect ~500-2000 iterations/second on a warm M-series. Corpus
discovery through TLS-handshake-adjacent ASN.1 shapes (name parsing,
extension walk) has historically taken libFuzzer hours to reach
useful depth, so plan for long runs.

## CI integration

The repo's CI does NOT run these by default — fuzz campaigns aren't
useful in short runs. Set up a dedicated fuzz runner (OSS-Fuzz, or a
scheduled GitHub Action that runs for an hour) if you want persistent
coverage tracking.

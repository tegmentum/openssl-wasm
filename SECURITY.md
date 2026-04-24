# Security Policy

## Supported Versions

`openssl-wasm` is pre-1.0. Security fixes land on `main` and ship in
the next tagged release. Older tags do not receive backports.

| Version | Supported          |
|---------|--------------------|
| `main`  | :white_check_mark: |
| `0.1.x` | :white_check_mark: |
| `< 0.1` | :x:                |

The OpenSSL submodule (`third_party/openssl`) is pinned to
`openssl-3.6.2`. CVEs against that pin are tracked here even if the
upstream fix has shipped — we update the pin and re-test the WIT
surface.

## Reporting a vulnerability

**Do not file a public issue.** Email
[security@tegmentum.ai](mailto:security@tegmentum.ai) with:

- a description of the issue,
- the commit / tag it reproduces against,
- a minimal proof-of-concept (host harness preferred, since it
  exercises the WIT surface the same way callers do).

You should expect an acknowledgement within 3 business days. We aim
to publish a fix and a CVE (where applicable) within 30 days for
high-severity issues affecting the component or the host glue.

PGP is available on request.

## Scope

In scope:

- Bugs in the C glue under `src/` that misuse the OpenSSL API in a
  way the C compiler / wasm sandbox cannot catch (e.g. wrong key
  length silently accepted, AEAD tag check bypass, double-free).
- WIT-surface flaws that let a malicious caller corrupt component
  state across resource handles.
- Cryptographic mis-use: nonce reuse, predictable IV defaults,
  silent fallback to weaker primitives, key material leaking through
  error paths.
- Build-system issues that produce a component lacking a security
  property the docs claim (e.g. README says "constant-time", build
  flag accidentally disables it).

Out of scope:

- Vulnerabilities in OpenSSL itself — report those upstream at
  <https://www.openssl.org/news/vulnerabilities.html> and we will
  bump the pin once a fix lands.
- Side-channel attacks that require co-resident execution on the
  same physical host as the wasm runtime; the threat model in
  `README.md` excludes them explicitly.
- Issues that require the host to feed a non-CSPRNG to
  `wasi:random`, a substituted CA bundle through `wasi:filesystem`,
  or otherwise compromise the wasmtime sandbox itself. The component
  trusts its host.
- Denial-of-service via unbounded inputs at the WIT boundary —
  callers are expected to size-cap their own buffers; we will fix
  these on a best-effort basis but they are not embargoed.

## Hardening status

See `README.md` § Security notes for the constant-time inventory
(what OpenSSL guarantees vs. what we explicitly call out as
data-dependent) and the wasm sandbox threat model.

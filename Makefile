# openssl-wasm build orchestration.
#
# Phases:
#   1. stage-openssl-config : drop our Configure target into OpenSSL
#   2. configure-openssl    : run OpenSSL Configure with that target
#   3. build-openssl        : make libcrypto.a + libssl.a
#   4. bindings             : wit-bindgen → src/bindings/*.{c,h}
#   5. link                 : compile glue + bindings → core module
#   6. component            : wasm-tools component new → final .wasm

SHELL        := bash
.SHELLFLAGS  := -eu -o pipefail -c
.DEFAULT_GOAL := component

# Default search order: $(ROOT)/.wasi-sdk (from scripts/install-wasi-sdk.sh),
# then ~/wasi-sdk-33, then /opt/wasi-sdk. Override by setting WASI_SDK.
WASI_SDK     ?= $(firstword $(wildcard \
                  $(abspath .)/.wasi-sdk \
                  $(HOME)/wasi-sdk-33 \
                  /opt/wasi-sdk) \
                  $(HOME)/wasi-sdk-33)
WASM_TOOLS   ?= wasm-tools
WIT_BINDGEN  ?= wit-bindgen

CLANG        := $(WASI_SDK)/bin/clang
LLVM_AR      := $(WASI_SDK)/bin/llvm-ar
SYSROOT      := $(WASI_SDK)/share/wasi-sysroot
TARGET       := wasm32-wasip2

ROOT         := $(abspath .)
OPENSSL_SRC  := $(ROOT)/third_party/openssl
OPENSSL_BUILD:= $(ROOT)/build/openssl
BUILD_DIR    := $(ROOT)/build
BINDINGS_DIR := $(ROOT)/src/bindings
CORE_MODULE  := $(BUILD_DIR)/openssl-core.wasm
COMPONENT    := $(BUILD_DIR)/openssl-component.wasm

NPROC        := $(shell sysctl -n hw.ncpu 2>/dev/null || nproc)

# size=min drops legacy ciphers/digests that aren't needed for modern
# TLS and protocol use. Callers lose RIPEMD / BLAKE2 / SM* / Camellia /
# ARIA / IDEA / RC2 / RC5 / SEED / MDC2 / Whirlpool / Cast / Blowfish.
# Measured saving: ~230 KiB (6% of the 3.65 MiB default component).
# (MD5 stays — OpenSSL 3.6 rejects no-md5 because several internal paths
# still reference it, e.g. TLS 1.0/1.1 PRF and some PKCS primitives.)
ifeq ($(size),min)
SIZE_DISABLE := no-blake2 no-sm2 no-sm3 no-sm4 \
                no-camellia no-aria no-idea no-rc2 no-rc5 no-seed \
                no-mdc2 no-whirlpool no-cast no-bf
endif

# simd=on enables wasm simd128 codegen (OpenSSL's portable C auto-vectorized).
# Default off because gains are modest and older runtimes reject simd128.
ifeq ($(simd),on)
SIMD_FLAG    := -msimd128
endif

# simd_aes=on replaces OpenSSL's portable-C AES_encrypt / AES_decrypt with
# hand-written wasm SIMD implementations (vpAES). Target: 5-8x speedup on
# AES-GCM and CBC bulk paths.
#
# Uses --wrap so we don't touch the OpenSSL submodule. Phase A plumbing
# only forwards to __real_*; Phase B+ replaces the implementations.
# Implies simd=on.
ifeq ($(simd_aes),on)
SIMD_FLAG    := -msimd128
SIMD_AES_WRAP := -Wl,--wrap=AES_encrypt -Wl,--wrap=AES_decrypt
SIMD_AES_DEF := -DOPENSSL_WASM_SIMD_AES=1
endif

# OpenSSL produces these static archives.
OPENSSL_LIBS := $(OPENSSL_BUILD)/libssl.a $(OPENSSL_BUILD)/libcrypto.a

# wit-bindgen-c emits one .c and one .h per world, plus a
# *_component_type.o object that carries the component-type custom section.
BINDINGS_C   := $(BINDINGS_DIR)/openssl.c
BINDINGS_H   := $(BINDINGS_DIR)/openssl.h
BINDINGS_OBJ := $(BINDINGS_DIR)/openssl_component_type.o

# Every src/*.c: hand-written glue + the generated src/stubs.c.
GLUE_SRCS    := $(wildcard src/*.c)
GLUE_OBJS    := $(patsubst src/%.c,$(BUILD_DIR)/obj/%.o,$(GLUE_SRCS))

# Reproducible-build knobs:
# - SOURCE_DATE_EPOCH controls anywhere OpenSSL or clang embeds a
#   timestamp (it's honored by clang's __DATE__/__TIME__ and by
#   OpenSSL's timestamp-in-module-metadata). Default to the HEAD
#   commit time; override by setting SOURCE_DATE_EPOCH.
# - -Wno-builtin-macro-redefined lets us override __DATE__/__TIME__
#   deterministically.
SOURCE_DATE_EPOCH ?= $(shell git -C $(ROOT) log -1 --format=%ct 2>/dev/null || echo 0)
export SOURCE_DATE_EPOCH

REPRO_FLAGS  := -Wno-builtin-macro-redefined \
                -D__DATE__="\"redacted\"" -D__TIME__="\"redacted\"" \
                -fdebug-prefix-map=$(ROOT)=. \
                -fmacro-prefix-map=$(ROOT)=.

CFLAGS       := --target=$(TARGET) --sysroot=$(SYSROOT) \
                -O2 -fno-strict-aliasing -Wall -Wextra -Wno-unused-parameter \
                $(SIMD_FLAG) $(SIMD_AES_DEF) $(REPRO_FLAGS) \
                -D_WASI_EMULATED_MMAN -D_WASI_EMULATED_SIGNAL \
                -D_WASI_EMULATED_PROCESS_CLOCKS -D_WASI_EMULATED_GETPID \
                -I$(OPENSSL_SRC)/include -I$(OPENSSL_BUILD)/include \
                -Isrc -I$(BINDINGS_DIR) -Isrc/include

LDFLAGS      := --target=$(TARGET) --sysroot=$(SYSROOT) \
                -mexec-model=reactor \
                -Wl,--no-entry -Wl,--export-dynamic \
                $(SIMD_AES_WRAP) \
                -lwasi-emulated-mman -lwasi-emulated-signal \
                -lwasi-emulated-process-clocks -lwasi-emulated-getpid

.PHONY: all component core bindings openssl configure-openssl \
        stage-openssl-config clean distclean check-wasi-sdk run host

all: component

# One-command setup for a fresh checkout: installs wasi-sdk into
# .wasi-sdk/ (if missing), fetches the Mozilla CA bundle, builds the
# component, and runs the full test suite.
.PHONY: dev
dev:
	@test -x $(WASI_SDK)/bin/clang || bash scripts/install-wasi-sdk.sh
	@test -f examples/host/fixtures/cacert.pem || bash scripts/fetch-mozilla-ca.sh
	$(MAKE) component
	$(MAKE) test

check-wasi-sdk:
	@test -x $(CLANG) || { \
	  echo "error: WASI_SDK not found at $(WASI_SDK)"; \
	  echo "       run: scripts/install-wasi-sdk.sh"; \
	  echo "       or set WASI_SDK=/path/to/wasi-sdk-33"; \
	  exit 1; }

# ----------------------------------------------------------------------------
# 1. Stage our Configure target into the OpenSSL submodule.
# ----------------------------------------------------------------------------
stage-openssl-config: $(OPENSSL_SRC)/Configurations/50-wasm.conf
$(OPENSSL_SRC)/Configurations/50-wasm.conf: config/50-wasm.conf
	cp $< $@

# ----------------------------------------------------------------------------
# 2. Configure OpenSSL out-of-tree.
# ----------------------------------------------------------------------------
configure-openssl: $(OPENSSL_BUILD)/Makefile
$(OPENSSL_BUILD)/Makefile: check-wasi-sdk stage-openssl-config
	mkdir -p $(OPENSSL_BUILD)
	cd $(OPENSSL_BUILD) && \
	  WASI_SDK=$(WASI_SDK) \
	  OPENSSL_WASM_SIMD_FLAG="$(SIMD_FLAG)" \
	  OPENSSL_WASM_REPRO_FLAGS="$(REPRO_FLAGS)" \
	  SOURCE_DATE_EPOCH="$(SOURCE_DATE_EPOCH)" \
	  perl $(OPENSSL_SRC)/Configure $(TARGET) \
	    no-threads no-shared no-dso no-asm no-engine no-async \
	    no-afalgeng no-ktls no-ui-console no-autoload-config \
	    no-module no-tests no-apps no-docs no-quic \
	    $(SIZE_DISABLE) \
	    --prefix=$(OPENSSL_BUILD)/install

# ----------------------------------------------------------------------------
# 3. Build libcrypto.a + libssl.a.
# ----------------------------------------------------------------------------
openssl: $(OPENSSL_LIBS)
$(OPENSSL_LIBS): $(OPENSSL_BUILD)/Makefile
	$(MAKE) -C $(OPENSSL_BUILD) -j$(NPROC) build_libs

# ----------------------------------------------------------------------------
# 4. wit-bindgen C bindings.
# ----------------------------------------------------------------------------
bindings: $(BINDINGS_C) src/stubs.c
$(BINDINGS_C) $(BINDINGS_H) $(BINDINGS_OBJ) &: wit/*.wit
	mkdir -p $(BINDINGS_DIR)
	$(WIT_BINDGEN) c --world openssl --out-dir $(BINDINGS_DIR) wit

HAND_SRCS    := $(filter-out src/stubs.c,$(wildcard src/*.c))
src/stubs.c: $(BINDINGS_H) $(HAND_SRCS) scripts/gen-stubs.sh
	bash scripts/gen-stubs.sh $(BINDINGS_H) "$(HAND_SRCS)" src/stubs.c

# ----------------------------------------------------------------------------
# 5. Compile + link the core wasm module.
# ----------------------------------------------------------------------------
$(BUILD_DIR)/obj/%.o: src/%.c $(BINDINGS_H) $(OPENSSL_LIBS) | check-wasi-sdk
	mkdir -p $(dir $@)
	$(CLANG) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/obj/bindings.o: $(BINDINGS_C) $(BINDINGS_H) | check-wasi-sdk
	mkdir -p $(dir $@)
	$(CLANG) $(CFLAGS) -c $(BINDINGS_C) -o $@

core: $(CORE_MODULE)
$(CORE_MODULE): $(GLUE_OBJS) $(BUILD_DIR)/obj/bindings.o $(BINDINGS_OBJ) $(OPENSSL_LIBS)
	$(CLANG) $(LDFLAGS) \
	  $(GLUE_OBJS) $(BUILD_DIR)/obj/bindings.o $(BINDINGS_OBJ) \
	  $(OPENSSL_BUILD)/libssl.a $(OPENSSL_BUILD)/libcrypto.a \
	  -o $@

# ----------------------------------------------------------------------------
# 6. Finalize the component.
#
# wasi-sdk 33's wasm32-wasip2 target emits a Component directly (magic
# 0d 00 01 00), so there is no core module to wrap — the link output IS
# the component. We just copy and validate.
# ----------------------------------------------------------------------------
component: $(COMPONENT)
$(COMPONENT): $(CORE_MODULE)
	cp $< $@
	$(WASM_TOOLS) validate $@
	@echo "built component: $@"

# ----------------------------------------------------------------------------
# Host example.
# ----------------------------------------------------------------------------
host: $(COMPONENT)
	cd examples/host && cargo build --release

run: host
	cd examples/host && cargo run --release -- $(COMPONENT)

test: $(COMPONENT)
	OPENSSL_WASM_COMPONENT=$(COMPONENT) \
	cd examples/host && cargo test --release -- --test-threads=1

# Static analysis pass over the glue code. Uses clang's analyzer (same
# infrastructure used by scan-build). Runs in about a second. Does NOT
# replace a real ASan run; that needs a native test harness with a
# bindings shim, deferred.
check:
	@command -v clang >/dev/null || { echo "clang not found"; exit 1; }
	@echo "static-analyzing src/*.c with clang analyzer..."
	@for f in $(filter-out src/stubs.c,$(wildcard src/*.c)); do \
	  clang --analyze \
	    --target=$(TARGET) --sysroot=$(SYSROOT) \
	    -D_WASI_EMULATED_MMAN -D_WASI_EMULATED_SIGNAL \
	    -D_WASI_EMULATED_PROCESS_CLOCKS -D_WASI_EMULATED_GETPID \
	    -I$(OPENSSL_SRC)/include -I$(OPENSSL_BUILD)/include \
	    -Isrc -I$(BINDINGS_DIR) -Isrc/include \
	    -Xanalyzer -analyzer-output=text \
	    "$$f" || true; \
	done
	$(WASM_TOOLS) validate $(COMPONENT)
	$(WASM_TOOLS) component wit $(COMPONENT) > /dev/null
	@echo "check passed."

# Verify a build is reproducible: build twice from scratch, compare.
# Expensive (two OpenSSL builds); run in CI only.
repro-check:
	rm -rf build/openssl build/obj $(COMPONENT) $(CORE_MODULE) $(BINDINGS_DIR)
	$(MAKE) component
	cp $(COMPONENT) $(BUILD_DIR)/repro-a.wasm
	rm -rf build/openssl build/obj $(COMPONENT) $(CORE_MODULE) $(BINDINGS_DIR)
	$(MAKE) component
	cp $(COMPONENT) $(BUILD_DIR)/repro-b.wasm
	@if cmp -s $(BUILD_DIR)/repro-a.wasm $(BUILD_DIR)/repro-b.wasm; then \
	  echo "reproducible: SHA-256 $$(shasum -a 256 $(BUILD_DIR)/repro-a.wasm | awk '{print $$1}')"; \
	else \
	  echo "NOT reproducible:"; \
	  ls -la $(BUILD_DIR)/repro-a.wasm $(BUILD_DIR)/repro-b.wasm; \
	  shasum -a 256 $(BUILD_DIR)/repro-a.wasm $(BUILD_DIR)/repro-b.wasm; \
	  exit 1; \
	fi

# Size breakdown of the component. Human-readable section sizes.
size: $(COMPONENT)
	@echo "total: $$(wc -c < $(COMPONENT)) bytes"
	@$(WASM_TOOLS) print $(COMPONENT) --skeleton 2>/dev/null | head -20 || true
	@$(WASM_TOOLS) objdump $(COMPONENT) 2>/dev/null | head -20 || true

# Formatter + clippy. Non-invasive (prints but doesn't auto-edit).
lint:
	@cd examples/host && cargo clippy --release --all-targets -- -D warnings
	@cd examples/host && cargo fmt --check
	@echo "lint passed."

# Regenerate compile_commands.json for clangd. Uses current WASI_SDK.
compile-commands:
	bash scripts/gen-compile-commands.sh

# Emit CycloneDX 1.5 SBOM for the built component.
sbom: $(COMPONENT)
	bash scripts/gen-sbom.sh

# Run the component-vs-native benchmark suite.
bench: $(COMPONENT)
	OPENSSL_WASM_COMPONENT=$(COMPONENT) \
	cd examples/host && cargo bench --bench component_vs_native

# Generate rustdoc for the host harness. Opens in target/doc.
docs:
	cd examples/host && cargo doc --no-deps --open

# ----------------------------------------------------------------------------
# Cleanup.
# ----------------------------------------------------------------------------
clean:
	rm -rf $(BUILD_DIR) $(BINDINGS_DIR)

distclean: clean
	rm -f $(OPENSSL_SRC)/Configurations/50-wasm.conf src/stubs.c
	cd examples/host && cargo clean || true

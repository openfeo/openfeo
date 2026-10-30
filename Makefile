# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Andrew Newton
KERNEL_VERSION ?= 6.18.59
TARGET         ?= x86_64-unknown-linux-musl
PROFILE        ?= release
FEATURES       ?= harness
BUILD          ?= $(CURDIR)/build
BUILD_ID       := $(shell git describe --always --dirty 2>/dev/null || echo dev)
FILTER         ?=

BIN := target/$(TARGET)/$(PROFILE)/openfeo

KERNEL_ENV := KERNEL_VERSION=$(KERNEL_VERSION) BUILD=$(BUILD)

.PHONY: bin kernel-src kernel run test-harness check-env ci lint test
bin:
	OPENFEO_BUILD_ID=$(BUILD_ID) cargo build -p openfeo --$(PROFILE) --target $(TARGET) $(if $(FEATURES),--features $(FEATURES))
kernel-src:
	$(KERNEL_ENV) kernel/build.sh fetch
kernel: bin kernel-src
	$(KERNEL_ENV) kernel/build.sh config $(CURDIR)/$(BIN)
	$(KERNEL_ENV) kernel/build.sh build
run: kernel
	cargo run -q -p openfeo-harness -- run --kernel $(BUILD)/bzImage
test-harness: kernel
	OPENFEO_KERNEL=$(BUILD)/bzImage cargo test -p openfeo-harness --test m0 -- $(FILTER)
check-env:
	cargo run -q -p openfeo-harness -- check
ci: lint test kernel test-harness
lint:
	cargo fmt --all --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings
	cargo clippy -p openfeo --all-targets -- -D warnings
	cargo deny check
	scripts/check-spdx.sh
test:
	cargo test --workspace --lib --bins --all-features
	cargo test -p openfeo

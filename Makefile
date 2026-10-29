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

.PHONY: bin kernel-src kernel lint test
bin:
	OPENFEO_BUILD_ID=$(BUILD_ID) cargo build -p openfeo --$(PROFILE) --target $(TARGET) $(if $(FEATURES),--features $(FEATURES))
kernel-src:
	$(KERNEL_ENV) kernel/build.sh fetch
kernel: bin kernel-src
	$(KERNEL_ENV) kernel/build.sh config $(CURDIR)/$(BIN)
	$(KERNEL_ENV) kernel/build.sh build
lint:
	cargo fmt --all --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings
	cargo deny check
	scripts/check-spdx.sh
test:
	cargo test --workspace --lib --bins --all-features

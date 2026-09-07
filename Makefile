# SPDX-License-Identifier: MIT
CC ?= cc
AR ?= ar
BPF_CLANG ?= clang
BPF_CFLAGS ?= -O2 -g -target bpf
PYTHON ?= python3
BUILD_DIR ?= build
FRESH_FULL_SWITCH ?= 0

VMLINUX_H := $(BUILD_DIR)/vmlinux.h
BPF_OBJ := $(BUILD_DIR)/scx_fresh.bpf.o
SKEL_H := $(BUILD_DIR)/scx_fresh.skel.h
CLIENT_HEADERS := src/freshqos.h include/scx_fresh_shared.h include/scx_execution_trace.h

.PHONY: all bpf client test test-scheduler-mode test-slice clean
all: $(BUILD_DIR)/scx_fresh client
bpf: $(SKEL_H)
client: $(BUILD_DIR)/libfreshqos.a

$(BUILD_DIR)/background_workload: tests/background_workload.c $(BUILD_DIR)/libfreshqos.a $(CLIENT_HEADERS)
	$(CC) -O2 -g -Wall -Wextra -Werror -Iinclude -Isrc $< $(BUILD_DIR)/libfreshqos.a -lbpf -lpthread -o $@

$(BUILD_DIR):
	mkdir -p "$@"

$(VMLINUX_H): | $(BUILD_DIR)
	scripts/gen_vmlinux_h.sh "$@"

$(BPF_OBJ): $(VMLINUX_H) bpf/scx_fresh.bpf.c bpf/background_server.h bpf/execution_trace.bpf.h $(CLIENT_HEADERS)
	$(BPF_CLANG) $(BPF_CFLAGS) -DFRESH_FULL_SWITCH=$(FRESH_FULL_SWITCH) -I$(BUILD_DIR) -Iinclude -Ibpf -c bpf/scx_fresh.bpf.c -o $@

$(SKEL_H): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

$(BUILD_DIR)/freshqos.o: src/freshqos.c $(CLIENT_HEADERS) | $(BUILD_DIR)
	$(CC) -O2 -g -fPIC -Iinclude -Isrc -c $< -o $@

$(BUILD_DIR)/libfreshqos.a: $(BUILD_DIR)/freshqos.o
	$(AR) rcs $@ $<

$(BUILD_DIR)/scx_fresh: src/scx_fresh_user.c bpf/background_server.h $(SKEL_H) $(BUILD_DIR)/libfreshqos.a $(CLIENT_HEADERS)
	$(CC) -O2 -g -I$(BUILD_DIR) -Iinclude -Isrc $< $(BUILD_DIR)/libfreshqos.a -lbpf -lelf -lz -o $@

test: test-scheduler-mode test-slice test-classes test-background

.PHONY: test-background
test-background:
	CC="$(CC)" $(PYTHON) tests/test_background_server.py

.PHONY: test-classes
test-classes:
	CC="$(CC)" $(PYTHON) tests/test_service_classes.py

test-scheduler-mode: $(BUILD_DIR)/scx_fresh
	LOADER_BIN="$(abspath $(BUILD_DIR)/scx_fresh)" EXPECTED_FULL_SWITCH="$(FRESH_FULL_SWITCH)" $(PYTHON) tests/test_scheduler_mode.py

test-slice: $(VMLINUX_H)
	VMLINUX_H="$(abspath $(VMLINUX_H))" CC="$(CC)" $(PYTHON) tests/test_enqueue_slice.py

clean:
	rm -rf "$(BUILD_DIR)"

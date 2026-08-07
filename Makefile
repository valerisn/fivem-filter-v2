# SPDX-License-Identifier: GPL-2.0
CLANG      ?= clang
CC         ?= cc
BPFTOOL    ?= bpftool
LLVM_STRIP ?= llvm-strip
PREFIX     ?= /usr/local
ARCH       := $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/;s/ppc64le/powerpc/;s/mips.*/mips/;s/riscv64/riscv/')

SRC        := src
BUILD      := build

BPF_CFLAGS := -O2 -g -Wall -Werror -target bpf -D__BPF__ -D__TARGET_ARCH_$(ARCH) \
              -I$(SRC) -I/usr/include/$(shell uname -m)-linux-gnu
CFLAGS     ?= -O2 -g -Wall -Wextra -Wno-unused-parameter
CFLAGS     += -I$(SRC)
LDLIBS     := -lbpf -lelf -lz

BPF_OBJ    := $(BUILD)/filter.bpf.o
CTL        := $(BUILD)/fivemctl

.PHONY: all clean install uninstall verify check-deps test

all: $(BPF_OBJ) $(CTL)

# Unit tests for the pure-arithmetic parts, runnable without root or a kernel.
test: | $(BUILD)
	$(CC) $(CFLAGS) tests/test_bogon.c -o $(BUILD)/test_bogon
	@$(BUILD)/test_bogon

$(BUILD):
	@mkdir -p $(BUILD)

$(BPF_OBJ): $(SRC)/filter.bpf.c $(SRC)/common.h | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@# Strip DWARF but keep BTF: the verifier wants BTF, nothing wants DWARF here.
	@$(LLVM_STRIP) -g $@ 2>/dev/null || true

$(CTL): $(SRC)/fivemctl.c $(SRC)/common.h | $(BUILD)
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

# Load the program into the kernel and immediately unload it. Catches verifier
# rejections without touching a live interface.
verify: $(BPF_OBJ)
	$(BPFTOOL) prog load $(BPF_OBJ) /sys/fs/bpf/ff-verify-test type xdp && \
		$(BPFTOOL) prog show pinned /sys/fs/bpf/ff-verify-test && \
		rm -f /sys/fs/bpf/ff-verify-test && echo "verifier OK"

check-deps:
	@command -v $(CLANG) >/dev/null || { echo "missing: clang"; exit 1; }
	@echo '#include <bpf/libbpf.h>' | $(CC) -E - >/dev/null 2>&1 || \
		{ echo "missing: libbpf-dev (>= 0.7, for bpf_xdp_attach)"; exit 1; }
	@echo "dependencies OK"

install: all
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/lib/fivem-xdp-filter
	install -m 0755 $(CTL) $(DESTDIR)$(PREFIX)/bin/fivemctl
	install -m 0644 $(BPF_OBJ) $(DESTDIR)$(PREFIX)/lib/fivem-xdp-filter/filter.bpf.o
	install -d $(DESTDIR)/etc/systemd/system
	install -m 0644 systemd/fivem-filter.service $(DESTDIR)/etc/systemd/system/

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/fivemctl
	rm -rf $(DESTDIR)$(PREFIX)/lib/fivem-xdp-filter
	rm -f $(DESTDIR)/etc/systemd/system/fivem-filter.service

clean:
	rm -rf $(BUILD)

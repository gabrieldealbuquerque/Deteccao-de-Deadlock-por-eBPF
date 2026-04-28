# Mission Control Lab — host: vmlinux.h, BPF, skeleton, loader; apps no Docker.
KERNEL_BTF ?= /sys/kernel/btf/vmlinux
CLANG ?= clang
LLC ?= llc
BPFTOOL ?= bpftool
ARCH ?= $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')

CFLAGS_LOADER := -O2 -g -Wall -Wextra $(shell pkg-config --cflags libbpf 2>/dev/null)
LDFLAGS_LOADER := $(shell pkg-config --libs libbpf 2>/dev/null) -lelf -lz

BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
	-Wall -Wextra -Wno-unused-value -Wno-pointer-sign \
	-Wno-compare-distinct-pointer-types

.PHONY: all clean vmlinux apps docker

all: vmlinux.h deadlock_bpf.o deadlock_bpf.skel.h loader apps

vmlinux.h:
	@test -r "$(KERNEL_BTF)" || (echo "Falta $(KERNEL_BTF). Use Linux com BTF habilitado." && false)
	@command -v $(BPFTOOL) >/dev/null || (echo "Instale bpftool (ex.: apt install linux-tools-\$$(uname -r))." && false)
	@command -v $(CLANG) >/dev/null || (echo "Instale clang e llvm." && false)
	$(BPFTOOL) btf dump file $(KERNEL_BTF) format c > $@.tmp
	mv -f $@.tmp $@

deadlock_bpf.o: deadlock_bpf.c vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c deadlock_bpf.c -o $@

deadlock_bpf.skel.h: deadlock_bpf.o
	$(BPFTOOL) gen skeleton deadlock_bpf.o > $@

loader: loader.c deadlock_bpf.skel.h
	$(CC) $(CFLAGS_LOADER) -o $@ loader.c $(LDFLAGS_LOADER)

apps:
	$(MAKE) -f Makefile.apps

docker:
	docker compose build

clean:
	rm -f vmlinux.h deadlock_bpf.o deadlock_bpf.skel.h loader app_a app_b

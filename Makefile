.PHONY : all
all : connect.btf.o ebpf-loader

.PHONY : clean
clean :
	rm vmlinux.h connect.btf.o ebpf-loader

vmlinux.h :
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

CLANG_OPTIONS = -target bpf -g -O2
CLANG_OPTIONS += -Wno-unused-value
CLANG_OPTIONS += -Wno-pointer-sign
CLANG_OPTIONS += -Wno-compare-distinct-pointer-types
CLANG_OPTIONS += -Wno-gnu-variable-sized-type-not-at-end
CLANG_OPTIONS += -Wno-address-of-packed-member
CLANG_OPTIONS += -Wno-tautological-compare
CLANG_OPTIONS += -Wno-unknown-warning-option
CLANG_INCLUDES += -I "/usr/include"
CLANG_INCLUDES += -I "/usr/include/$(shell uname -m)-linux-gnu"

connect.btf.o : connect.bpf.c vmlinux.h
	clang $(CLANG_OPTIONS) $(CLANG_INCLUDES) -c $< -o $@

ebpf-loader : ebpf_loader.cpp
	g++ -O3 --std=c++17 -Wall -o $@ $< -lbpf

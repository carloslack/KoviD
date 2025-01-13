# Default target: build both the eBPF object and the user program
all: socket_filter_bpf.o socket_filter

# 1) Build the eBPF bytecode
socket_filter_bpf.o: socket_filter_bpf.c
	clang -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -c $< -o $@ -I ./

# 2) Build the user-space loader
socket_filter: main.c
	clang -o $@ $< \
	    -I/usr/include \
	    -L/usr/lib64 -lbpf -lelf -lz

# Cleanup
clean:
	rm -f socket_filter_bpf.o socket_filter

.PHONY: all clean

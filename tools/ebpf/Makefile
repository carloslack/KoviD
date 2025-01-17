# Default target: build both the eBPF object and the user program
all: socket_filter_bpf.o ebpf-kovid

# 1) Build the eBPF bytecode
socket_filter_bpf.o: socket_filter_bpf.c
	clang -O2 -g -Wall -I/usr/include/x86_64-linux-gnu/ -target bpf -D__TARGET_ARCH_x86 -c $< -o $@ -I ./

# 2) Build the user-space loader
ebpf-kovid: main.c
	clang -o $@ $< \
	    -I/usr/include \
	    -L/usr/lib64 -lbpf -lelf -lz

install: socket_filter_bpf.o ebpf-kovid
	sudo cp socket_filter_bpf.o /usr/bin/socket_filter_bpf.o
	sudo cp ebpf-kovid /usr/bin/ebpf-kovid
	@echo "Installed eBPF artifacts into /usr/bin/"

# Cleanup
clean:
	rm -f socket_filter_bpf.o ebpf-kovid

.PHONY: all clean

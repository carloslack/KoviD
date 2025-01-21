# ebpf-kovid eBPF tool

This folder contains two files demonstrating a simple eBPF socket filter:

- **socket_filter_bpf.c**: The eBPF program that inspects IPv4 TCP packets and increments counters if the destination port is 22 (SSH) or 443 (HTTPS).
- **main.c** (or **ebpf-kovid** after compilation): A user-space loader that:
  - Loads the eBPF bytecode (`socket_filter_bpf.o`) into the kernel.
  - Creates a raw packet socket (AF_PACKET).
  - Attaches the eBPF program as a socket filter.
  - Periodically reads and prints the per-port packet counters.

## Building

Just run:

```bash
$ make all
$ sudo make install
sudo cp socket_filter_bpf.o /usr/bin/socket_filter_bpf.o
sudo cp ebpf-kovid /usr/bin/ebpf-kovid
Installed eBPF artifacts into /usr/bin/
```

## Usage

Make sure you have libbpf, libelf, and zlib installed (e.g., `sudo apt-get install libbpf-dev libelf-dev zlib1g-dev clang` on Debian/Ubuntu).

```bash
$ sudo ./ebpf-kovid
```

## Load it from LKM

```
$ sudo echo "exec-ebpf" > /proc/myprocname
```

The output is in `/tmp/ebpf_kovid.json`.

You can test it as:

```
$ python3 -m http.server 8080 --bind 127.0.0.1

# another terminal
$ wget http://127.0.0.1:8080/
```

# socket_filter eBPF tool

This folder contains two files demonstrating a simple eBPF socket filter:

- **socket_filter_bpf.c**: The eBPF program that inspects IPv4 TCP packets and increments counters if the destination port is 22 (SSH) or 443 (HTTPS).
- **main.c** (or **socket_filter_user** after compilation): A user-space loader that:
  - Loads the eBPF bytecode (`socket_filter_bpf.o`) into the kernel.
  - Creates a raw packet socket (AF_PACKET).
  - Attaches the eBPF program as a socket filter.
  - Periodically reads and prints the per-port packet counters.

## Building

Just run:

```bash
$ make all
```

## Usage

Make sure you have libbpf, libelf, and zlib installed (e.g., sudo apt-get install libbpf-dev libelf-dev zlib1g-dev on Debian/Ubuntu).

```bash
$ sudo ./socket_filter_user
Port 22 => 3 packets
Port 443 => 5 packets
------
```

## Load it from LKM

***TODO***:

Since this eBPF program runs completely in user space, we can run the program from our LKM with `call_usermodehelper` . For example:

```
echo "monitor-http-tcp" > /proc/myprocname
```

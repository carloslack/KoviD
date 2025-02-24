# ebpf-kovid eBPF tool

This tool performs HTTP tracking using `eBPF` and can be extended to include additional features by leveraging `eBPF`'s capabilities.

## Build

From root folder, run:

```
$ make all build-ebpf PROCNAME="myprocname" TEST_ENV=1
$ sudo make install-ebpf TEST_ENV=1
```

## Usage

Make sure you have libbpf, libelf, and zlib installed (e.g., `sudo apt-get install libbpf-dev libelf-dev zlib1g-dev clang` on Debian/Ubuntu).

```bash
$ sudo $/path/to/ebpf-kovid
```

## Load it from LKM

```
$ sudo /usr/bin/$(EBPFHIDEKEY)/ebpf-kovid
```

The output is in `/path/to/ebpf_kovid.json`.

You can test it as:

```
$ python3 -m http.server 8080 --bind 127.0.0.1

# another terminal
$ wget http://127.0.0.1:8080/
```

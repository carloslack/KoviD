# Testing of KoviD LKM

This document describes our comprehensive testing strategy for KoviD LKM. Our approach encompasses two primary methods:

*Native Tests*: These run directly on the host system using the locally installed Linux kernel, with a primary focus on kernel 5.15 (as our day-to-day development and testing are based on Ubuntu 20.04 with x86_64 target). This ensures core functionality and stability in our main development environment.

*Cross Tests*: Executed within a QEMU emulator using prebuilt Linux kernel images (currently supporting kernel 5.15 only), these tests provide a consistent and reproducible environment for verifying compatibility across different kernel versions.

You do not have to run both tests - you can pick what you want to test. See bellow!

## Contents

- [Testing of KoviD LKM](#testing-of-kovid-lkm)
  - [Current Focus and Experimental Support](#current-focus-and-experimental-support)
  - [Testing and Regression](#testing-and-regression)
  - [Build KoviD LKM](#build-kovid-lkm)
  - [Install dependecies and set up enviroment](#install-dependecies-and-set-up-enviroment)
    - [Some potential issues](#some-potential-issues)
  - [Building with custom Linux other than host](#building-with-custom-linux-other-than-host)
  - [Native Tests](#native-tests)
  - [Cross Tests](#cross-tests)
    - [Importance of Cross Tests](#importance-of-cross-tests)
    - [Test Artifacts](#test-artifacts)
    - [Fetch LFS and submodules](#fetch-lfs-and-submodules)
  - [How to Write tests?](#how-to-write-tests)
    - [Cross](#cross)
    - [Native](#native)
    - [Additional test Markers](#additional-test-markers)
  - [Run tests](#run-tests)
  - [Testing status](#testing-status)
    - [Linux Kernel 5.15](#linux-kernel-515)
      - [Testing Status](#testing-status)
    - [Testing Azure - Linux Kernel 6.5.0](#testing-with-azure)
    - [Testing Android](#testing-android)
    - [Testing OSX](#testing-osx)

## Current Focus and Experimental Support

Linux kernel 5.x is thoroughly supported and extensively tested on a daily basis. Although Linux kernel 6.x (with CI/CD tests running on Linux 6.5.0 - see bellow) has been proven to work and several issues have been addressed, it remains experimental due to less frequent manual testing.

## Testing and Regression

Our testing process combines detailed manual testing with automated regression testing. We leverage the LLVM Lit infrastructure (see LLVM Lit Documentation https://llvm.org/docs/CommandGuide/lit.html) for regression tests. While some tests are straightforward to implement, others face challenges due to dependencies on external tools and complex scenarios.

This dual approach enables us to maintain a high level of reliability on our primary platform while steadily expanding support to additional kernel versions.

The regression tests are located in the `test/` directory of the project and are divided into two main categories:

1. Native Tests (`test/native`)
2. Cross Tests

We will cover `how-to-build` the project first and then describe the testing infrastructure.
Then, at least, we recommend at least to follow [Native Tests](#Native-Tests) and run those.

## Build KoviD LKM

To build `KoviD` LKM, for testing, use following:

```
$ cd KoviD && make PROCNAME="myprocname" TEST_ENV=1
```

## Install dependecies and set up enviroment

Lets set up enviroment for testing.

```
$ sudo apt  install cmake
$ sudo apt install g++
```

Please make sure to install llvm-tools, since we will be using some of the tools for testing infrastructure:

```
sudo apt-get install llvm-18-dev
sudo apt-get install llvm-18-tools
sudo apt install python3-pip
sudo apt-get install libslirp-dev
sudo apt-get install qemu-system-x86
sudo apt install netcat nmap
sudo apt-get -y install socat
```

On an older Ubuntu, follow https://apt.llvm.org/.
For example:

```
$ sudo bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)"
```

If you do not have `llvm-lit` installed, do:

```
$ pip3 install lit
$ sudo ln -s ~/.local/bin/lit /usr/bin/llvm-lit
$ which llvm-lit
/usr/bin/llvm-lit
```

NOTE: Make sure you set up `openssl` before running tests.

### Some potential issues

On Ubuntu 20.04, if you see:

```
$ sudo scripts/bdclient.sh nc localhost 9999
nc: getnameinfo: Temporary failure in name resolution
```

Just fix DNS server, e.g. by adding `0.0.0.0 localhost` into `/etc/hosts`.

## Building with custom Linux other than host

This is needed if you want to run *Cross Tests*, or if you want to "cross" compile the LKM for a Linux version that is different than the one you run on your PC.

```
$ cd KoviD && mkdir build && cd build 
$ cmake ../ -DKOVID_LINUX_VERSION=5.15 -DCMAKE_C_COMPILER=gcc-12 && make CC=gcc-12
-- The C compiler identification is GNU 12.3.0
-- The CXX compiler identification is GNU 11.4.0
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Check for working C compiler: /usr/bin/gcc-12 - skipped
-- Detecting C compile features
-- Detecting C compile features - done
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Check for working CXX compiler: /usr/bin/c++ - skipped
-- Detecting CXX compile features
-- Detecting CXX compile features - done
CMake Error at CMakeLists.txt:14 (message):
  Kernel headers for version 5.15 not found in /lib/modules/5.15/build


-- Configuring incomplete, errors occurred!
See also "build/CMakeFiles/CMakeOutput.log".
```

You faced an error. OK. Lets say we built `linux` in `projects/private/kovid/linux`, we can set up manually the variables:

```
$ cmake ../ -DKOVID_LINUX_VERSION=5.15 -DKERNEL_DIR=projects/private/kovid/linux -DKOVID_LINUX_VERSION=5.15 -DCMAKE_C_COMPILER=gcc
-- The C compiler identification is GNU 11.4.0
-- The CXX compiler identification is GNU 11.4.0
-- Detecting C compiler ABI info
-- Detecting C compiler ABI info - done
-- Check for working C compiler: /usr/bin/gcc - skipped
-- Detecting C compile features
-- Detecting C compile features - done
-- Detecting CXX compiler ABI info
-- Detecting CXX compiler ABI info - done
-- Check for working CXX compiler: /usr/bin/c++ - skipped
-- Detecting CXX compile features
-- Detecting CXX compile features - done
-- Linux Target: 5.15
-- Linux Headers: projects/private/kovid/linux
-- Extra CFLAGS: -Iprojects/private/kovid/linux/include -Iprojects/private/kovid/KoviD/src -Iprojects/private/kovid/KoviD/fs -I$(KERNEL_DIR)/include/generated -Wno-error -DPROCNAME="changeme" -DMODNAME="kovid" -DKSOCKET_EMBEDDED -DDEBUG_RING_BUFFER -DCPUHACK -DPRCTIMEOUT=1200 -DUUIDGEN="5a803031-366c-4070-8656-1f940a2467b8" -DJOURNALCTL="/usr/bin/journalctl"
-- Configuring done
-- Generating done
-- Build files have been written to: projects/private/kovid/build
$ make PROCNAME="mykovidproc"
-- Selected PROCNAME is mykovidproc
```

If you miss the `PROCNAME`, it will emit an error during build time:

```
$ make
...
*** ERROR: PROCNAME is not defined. Please invoke make with PROCNAME="your_process_name".  Stop.
```

## Native Tests

Those are locatet within `test/native`.

These tests run natively on the host system without the need for emulation or virtualization.
They verify the functionality of the LKM in the environment where it is developed, ensuring compatibility and stability on the host system.
To simply run those (but make sure you followed the instructions for setting the enviroment described below):

    ```
    $ cd KoviD && make PROCNAME="myprocname" TEST_ENV=1
    # From root directory of the project
    $ mkdir build && cd build
    $ cmake ../ -DCMAKE_C_COMPILER=gcc -DLLVM_DIR=/usr/lib/llvm-18/cmake && make PROCNAME="myprocname" TEST_ENV=1
    # Please run the command with only one Thread!
    $ make check-kovid -j1
    ```

NOTE: You will be asked for `sudo` password.

## Cross Tests

These tests run on a QEMU emulator, allowing testing on different Linux kernel versions or architectures.
Subcategories:
1. Simple Cross Tests (`test/cross`):
    - Run entirely within the QEMU guest environment.
    - Essential for validating the LKM in a controlled setting that simulates different kernel versions.
2. Complex Cross Tests (`test/complex`):
    - Partially run on QEMU and partially on the host system.
    - Designed to test the interaction between the guest and host environments, ensuring proper communication and handshake in various scenarios.

### Importance of Cross Tests

Cross tests are crucial when you need to compile and test the LKM for a Linux version that is different from the one used on your host PC. They provide the infrastructure for both the compilation and testing of such Linux versions. This is particularly important for:

    1. Compatibility Testing: Ensuring that the LKM works correctly across different kernel versions.
    2. Regression Testing: Identifying any issues that may arise when the module is used in environments other than the development system.

### Test Artifacts

Currently, the project supports testing with Linux kernel version 5.10. The necessary test artifacts, including the Linux image and root filesystem (rootfs), are provided as a git submodule. These artifacts are located in the test/test-artefacts/ directory.
Benefits of Using Test Artifacts

    Consistency: Provides a standardized environment for testing, leading to reproducible results.
    Convenience: Simplifies the setup process, as the required images and files are readily available within the project structure.

Setting Up the Tests

To get started with testing:

    Initialize Submodules: Ensure that all submodules are initialized and updated to obtain the test artifacts.
        Use the command: git submodule update --init --recursive.

    Configure the Build Environment:
        Specify the desired kernel version.
        Provide the path to the kernel headers if necessary.

    Running Native Tests:
        Navigate to the test/native directory.
        Execute the test scripts as needed.

    Running Cross Tests:
        For simple cross tests, navigate to test/cross and follow the provided instructions.
        For complex cross tests, navigate to test/complex and ensure both guest and host components are properly configured.


### Fetch LFS and submodules

```
$ git fetch --recurse-submodules
```
or:

```
$ git submodule update --remote --recursive
```

LFS should be fetched:

```
$ git lfs fetch --all
```

Usual set of commands to be used:

```
$ git clone https://github.com/carloslack/KoviD.git main-KoviD && cd main-KoviD
$ git submodule update --init test/test-artefacts
$ mkdir build && cd build
$ cmake ../ -DKOVID_LINUX_VERSION=5.10 -DKERNEL_DIR=private/kovid/linux -DKOVID_LINUX_VERSION=5.10 -DCMAKE_C_COMPILER=gcc && make PROCNAME="myprocname" TEST_ENV=1 && make check-kovid
```

## How to Write tests?

Lets describe both native and cross tests.

### Cross

For those, we use `CROSS_TESTS` marker.
Each test consists of a pair of files:

    1) Bash Script (.sh file): A shell script that will be transferred to QEMU. It contains the set of commands we want to test.
    2) Expected Output (.test file): A file that contains the expected output for the test, which we use to verify that our feature is working as intended.

### Native

For those, we use `NATIVE_TESTS` marker.
This type of tests consists only one `.test` file, that contains both `bash` commands and expected output to check against.

### Additional test Markers

    - Deploy Mode Tests (# REQUIRES: DEPLOY_ONLY): Some tests are run only when the Loadable Kernel Module (LKM) is built in deploy mode. These tests have a .test file marked with # DEPLOY_ONLY at the top.
    - Debug Mode Tests (# REQUIRES: DEBUG_ONLY): Tests that should only run in debug mode are marked with # DEBUG_ONLY in their .test files.
    - If a test does not have any of these marker, it will be run in each mode.

## Run tests

Run tests (for `native` tests, you will be asked for `sudo` password):

```
$ make check-kovid -j1
```

Run tests in `DEPLOY` mode (some tests are run in this mode only; this is example for `cross` tests):

```
$ cmake ../ -DKOVID_LINUX_VERSION=5.10 -DKERNEL_DIR=projects/private/kovid/linux -DKOVID_LINUX_VERSION=5.10 -DCROSS_TESTS=ON -DCMAKE_C_COMPILER=gcc -DDEPLOY=1 -DNATIVE_TESTS=OFF
$ make PROCNAME="myprocname" DEPLOY=1 TEST_ENV=1
$ make check-kovid
```

## Testing status

Here are information about testing of the features available.

### Linux Kernel 5.15

All features listed bellow are being tested since v2.1.1, so it used to work since then, and should keep working in the future versions of KoviD.

NOTE: If a test should be executed in `DEPLOY` mode only, `.test` file should contain `# REQUIRES: DEPLOY_ONLY` marker.

| Feature                                            | Tested                         | Regression Test                                        |
| :--------------------------------------------------| :------------------------------| :------------------------------------------------------|
| Simple insmod/rmmod of KoviD                       | Yes                            | native/simple-insmod-lkm.test                          |
| Hide process                                       | Yes                            | cross/hide-pid.test                                    |
| Extract base address of a running process          | Yes                            | cross/extract-base-address.test                        |
| anti-rk's that are available (bpf-hookdetect)      | No (hard to test on qemu)      | None                                                   |
| anti-rk's that are available (rkspotter)           | No (build for non host kernel) | None                                                   |
| anti-rk's that are available (rkbreaker)           | No (build for non host kernel) | None                                                   |
| Simple netcat reverse shell                        | No (understand bdclient)       | None                                                   |
| Log tty keys and steal passwords over SSH (and FTP)| No (understand bdclient)       | None                                                   |
| Simple persistence using ELF infection with Volundr| No (understand bdclient)       | None                                                   |
| Hide pre-defined network application               | Yes                            | None                                                   |
| No tainted messages/log appear in DEPLOY           | Yes                            | cross/no-kovid-logs-in-deploy.test                     |
| kovid (DEPLOY) doesn't appear in /var /sys etc.    | Yes                            | cross/no-kovid-found.test                              |
| Hide/Unhide Module Test in DEBUG Mode              | Yes                            | cross/hide-unhide-module.test                          |
| Hide nc process                                    | Yes                            | complex/nc-hide-pid{_host}.test                        |
| nc backdoor                                        | Yes                            | native/nc-backdoor.test                                |
| openssl backdoor                                   | Yes                            | native/openssl-backdoor.test                           |
| tty backdoor                                       | Yes                            | native/tty-backdoor.test                               |
| backdoor echo -s                                   | Yes                            | native/nc-backdoor-echo-s.test                         |
| Hide/Unhide Module                                 | Yes                            | native/hide-unhide-module.test                         |
| backdoor + PID                                     | Yes                            | native/nc-backdoor-plus-pid.test                       |
| hide file                                          | Yes                            | native/hiden-file.test                                 |
| hide file (2)                                      | Yes                            | native/hiden-file-in-all-dirs.test                     |
| procfile timeout                                   | Yes                            | native/proc-timeout.test                               |
| Ftrace - simple test                               | Yes                            | native/ftrace-disable-enable.test                      |
| Remove netcat and install again (backdoors)        | Yes                            | native/nc-backdoor-remove-and-install-nc-tool.test     |
| bdclient.sh test                                   | Yes                            | native/nc-backdoor-bdclient.test                       |
| bdclient.sh GIFT                                   | Yes                            | test/native/gift-bdclient.test                         |
| Kaudit                                             | Yes                            | test/native/kaudit.test                                |
| list backdoors+test backdoor names                 | Yes                            | test/native/backdoor-socket.test                       |
| Extract base address from ELF file                 | Yes                            | test/native/base-address-elf.test                      |
| Get backdor key                                    | Yes                            | test/native/get_bdkey.test                             |
| Get key for module hinde/unhide                    | Yes                            | test/native/get_unhidekey.test                         |
| Get key for module hinde/unhide                    | Yes                            | test/native/get_unhidekey.test                         |
| backdoor hidden from standard connection           | Yes                            | test/native/hidden-network.test                        |
| Hide directory but still read from it              | Yes                            | test/native/hide-but-read-dir-file.test                |
| Hide directory links                               | Yes                            | test/native/hide-dir-test-links.test                   |
| Inject                                             | Yes                            | test/native/inject.test                                |
| Journal                                            | Yes                            | test/native/journal.test                               |
| list backdoors                                     | Yes                            | test/native/list-backdoors.test                        |
| list hidden files                                  | Yes                            | test/native/list-hidden-files.test                     |
| Hide the process using the backdoor functionality  | Yes                            | test/native/nc-backdoor-plus-pid.test                  |
| KoviD proc not visible                             | Yes                            | test/native/proc-not-visible.test                      |
| KoviD proc timeout                                 | Yes                            | test/native/proc-timeout.test                          |
| Rename hidden task                                 | Yes                            | test/native/rename-hidden-task.test                    |
| Pause/Resume/Kill hidden task                      | Yes                            | test/native/send-signals-to-tasks.test                 |
| Syslog clear (similar to `dmesg -c`)               | Yes                            | test/native/syslog-clear.test                          |
| "taint-clear" - resets /proc/sys/kernel/tainted    | Yes                            | test/native/taint-clear.test                           |

### Testing with Azure

On the machine we run CI/CD we use Linux Kernel 6.5.0.

Testing for the Kovid project is currently performed on Azure via CI/CD with a Linux kernel version `6.5.0`. All tests listed under section `v2.1.1 Testing` are validated automatically with the exception of the `openssl` and `tty` backdoor tests, which have been temporarily disabled due to automation challenges (via `# REQUIRES 0` workaround). While the `openssl` test is known to work when run manually, its initial setup is not yet automated (it is not trivial to setup `openssl` first time you run it); similarly, the `tty` test remains postponed until a suitable automation strategy is developed for that one. All other tests—from verifying that no tainted logs appear in `DEPLOY`/`DEBUG` modes to ensuring that, for example `ftrace` and `kaudit`, operate correctly—have been successfully integrated into the continuous testing pipeline on Azure. So, whenever you submit a PR, all those tests will be triggered!

### Testing Android

This is still marked as WIP.

This is the fastest method to get a running Android emulator. Since we don't need to customize the OS, these prebuilt images will do the job.

1. `mkdir aemu && cd aemu`
2. Create launch_emu.sh by copy&paste content from https://android.googlesource.com/platform/packages/apps/Car/tests/+/refs/heads/mirror-car-apps-aosp-release/tools/launch_emu.sh (there's no download link)
3. `./launch_emu.sh -i -a 11370359` (this is an Android build revision number from CI table)

```
$ ./launch_emu.sh -v "-show-kernel".
$ sdkroot/platform-tools/adb root
$ sdkroot/platform-tools/adb push kovid.ko /data/local/tmp
$ sdkroot/platform-tools/adb shell
$ cd /data/local/tmp
$ insmod kovid.ko
```

CI table: https://ci.android.com/builds/branches/aosp-main-throttled/grid?legacy=1.
Kernel source /w tags: https://android.googlesource.com/kernel/common

`KoviD` *can be loaded on prebuilt Android* with a custom kernel 6.6.9, but unfortunately, `CFI` breaks it very quickly.
We tried to avoid a complete building of AOSP, but it seems impossible because some kernel modules must exist on the disk image, so we can't change the kernel too much.

From our perspective, the next steps related to Android would be:

1. Prepare build environment for complete aosp with 5.15 (or similar), so we can play with kernel config without limitations
2. Tweking the config until KoviD is usable
3. Resolve issues, one by one, to support KoviD on the prebuilt kernel

### Testing OSX

Also marked as WIP, since we are exploring options in this area.

Modern macOS versions heavily restrict kernel-level development. Apple strongly discourages the use of Kernel Extensions (KEXTs) in favor of `DriverKit`, which runs entirely in user space. `DriverKit` serves as Apple’s replacement for KEXTs, providing a restricted environment (somewhat analogous to `eBPF` on Linux) that improves system security and stability at the cost of less direct kernel access.

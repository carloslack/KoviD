# Testing of KoviD LKM

This document describes the process of testing the features of Kovid LKM.

The tests are located in the `test/` directory of the project and are divided into two main categories:

1. Native Tests (`test/native`)
2. Cross Tests

We will cover host to build the project first and then describe the testing infrastructure.

## Build KoviD

Old way (using pre-existing GNU Makefile):
```
$ cd KoviD
$ make clean && make CC=gcc-12
```

New way by using CMake:

```
$ mkdir build && cd build
$ cmake ../ -DCMAKE_C_COMPILER=gcc-12 && make CC=gcc-12
```

or

```
$ cmake ../ && make
```

NOTE: You can customize it:

```
$ cmake -DPROCNAME=myproc -DMODNAME=mymodule ../
```

If you want to build and run native tests only, just use:

```
$ cmake ../ -DCMAKE_C_COMPILER=gcc && make PROCNAME="myprocname" TEST_ENV=1  
```

## Building for Linux version other than native

This is needed if you want to run cross tests, or if you want to "cross" compile the LKM for a Linux version that is different than the one you run on your PC.

```
$ cmake ../ -DKOVID_LINUX_VERSION=5.10 -DCMAKE_C_COMPILER=gcc-12 && make CC=gcc-12
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
  Kernel headers for version 5.10 not found in /lib/modules/5.10/build


-- Configuring incomplete, errors occurred!
See also "build/CMakeFiles/CMakeOutput.log".
```

But lets say we built `linux` in `projects/private/kovid/linux`, we can set up manually the variables:

```
$ cmake ../ -DKOVID_LINUX_VERSION=5.10 -DKERNEL_DIR=projects/private/kovid/linux -DKOVID_LINUX_VERSION=5.10 -DCMAKE_C_COMPILER=gcc
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
-- Linux Target: 5.10
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

## Native Tests (`test/native`)

    These tests run natively on the host system without the need for emulation or virtualization.
    They verify the functionality of the LKM in the environment where it is developed, ensuring compatibility and stability on the host system.
    To simply run those (but make sure you followed the instructions for setting the enviroment described below):

    ```
    # From root directory of the project
    $ mkdir build && cd build
    $ cmake ../ -DCMAKE_C_COMPILER=gcc && make PROCNAME="myprocname" TEST_ENV=1
    # Please run the command with only one Thread!
    $ make check-kovid -j1
    ```

NOTE: You will be asked for `sudo` password.

## Cross Tests

These tests run on a QEMU emulator, allowing testing on different Linux kernel versions or architectures.
Subcategories:
1. Simple Cross Tests (`test/cross`):
        Run entirely within the QEMU guest environment.
        Essential for validating the LKM in a controlled setting that simulates different kernel versions.
2. Complex Cross Tests (`test/complex`):
        Partially run on QEMU and partially on the host system.
        Designed to test the interaction between the guest and host environments, ensuring proper communication and handshake in various scenarios.

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

## Insall dependecies and set up enviroment

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

## Some potential issues

On Ubuntu 20.04, if you see:

```
$ sudo scripts/bdclient.sh nc localhost 9999
nc: getnameinfo: Temporary failure in name resolution
```

Just fix DNS server, e.g. by adding `0.0.0.0 localhost` into `/etc/hosts`.

## How to Write tests?

### Cross (marker `CROSS_TESTS`)

Each test consists of a pair of files:

    1) Bash Script (.sh file): A shell script that will be transferred to QEMU. It contains the set of commands we want to test.
    2) Expected Output (.test file): A file that contains the expected output for the test, which we use to verify that our feature is working as intended.

### Native (marker `NATIVE_TESTS`)

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
$ cmake ../ -DKOVID_LINUX_VERSION=5.10 -DKERNEL_DIR=projects/private/kovid/linux -DKOVID_LINUX_VERSION=5.10 -DCROSS_TESTS=ON -DCMAKE_C_COMPILER=gcc -DDEPLOY=1
$ make PROCNAME="myprocname" DEPLOY=1 TEST_ENV=1
$ make check-kovid
```

## Testing status

Here are information about testing of the features available.

### Linux Kernel 5.10

| Feature                                            | Tested                         | Regression Test                    |
| :--------------------------------------------------| :------------------------------| :--------------------------------- |
| Hide process                                       | Yes                            | cross/hide-pid.test                |
| Extract base address of a running process          | Yes                            | cross/extract-base-address.test    |
| anti-rk's that are available (bpf-hookdetect)      | No (hard to test on qemu)      | None                               |
| anti-rk's that are available (rkspotter)           | No (build for non host kernel) | None                               |
| anti-rk's that are available (rkbreaker)           | No (build for non host kernel) | None                               |
| Simple netcat reverse shell                        | No (understand bdclient)       | None                               |
| Log tty keys and steal passwords over SSH (and FTP)| No (understand bdclient)       | None                               |
| Simple persistence using ELF infection with Volundr| No (understand bdclient)       | None                               |
| Hide pre-defined network application               | Yes                            | None                               |

#### 2.1.1 Testing

NOTE: If a test should be executed in `DEPLOY` mode only, `.test` file should contain `# REQUIRES: DEPLOY_ONLY` marker.

| Feature                                            | Tested                         | Regression Test                       |
| :--------------------------------------------------| :------------------------------| :------------------------------------ |
| No tainted messages/log appear in DEPLOY           | Yes                            | cross/no-kovid-logs-in-deploy.test    |
| kovid (DEPLOY) doesn't appear in /var /sys etc.    | Yes                            | cross/no-kovid-found.test             |
| Hide/Unhide Module Test in DEBUG Mode              | Yes                            | cross/hide-unhide-module.test         |
| Hide nc process                                    | Yes                            | complex/nc-hide-pid{_host}.test       |
| nc backdoor                                        | Yes                            | native/nc-backdoor.test               |
| openssl backdoor                                   | Yes                            | native/openssl-backdoor.test          |
| tty backdoor                                       | Yes                            | native/tty-backdoor.test              |
| backdoor echo -s                                   | Yes                            | native/nc-backdoor-echo-s.test        |
| Hide/Unhide Module                                 | Yes                            | native/hide-unhide-module.test        |
| backdoor + PID                                     | Yes                            | native/nc-backdoor-plus-pid.test      |
| hide file                                          | Yes                            | native/hiden-file.test                |
| hide file (2)                                      | Yes                            | native/hiden-file-in-all-dirs.test    |
| unhide module                                      | Yes                            | native/hide-unhide-module.test        |

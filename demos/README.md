# Demos

## Simple netcat reverse shell
![revshell](simple.gif?raw=true)

## Hide process & CPU usage
##### CPU usage is handled automatically if the process is hidden.
![cpu](cpu.gif?raw=true)
> Pro-tip: don't use 100% of all available CPU's at the same time

## Log tty keys and steal passwords over SSH (and FTP)
![keylog](tty.gif?raw=true)
> Gotcha: mistyped and copy & paste keys will not be logged

## Extract base address of a running process
![vm->start](base_address.gif?raw=true)

## Block BPF syscall stack analysis for hooked functions
##### BPF tools will fail if attempting to read from syscall stack traces. KoviD clears the stack trace and will force an error.
##### So if the application ignores the error code it will then not be able to read the stack.
![BPF](bpf.gif?raw=true)
> [bpf-hookdetect](https://github.com/pathtofile/bpf-hookdetect) possible false positives for sys_getdents - KoviD does not hook sys_getdents family.

## Simple persistence using ELF infection with Volundr
##### Persist rootkit between reboots with the help of [Volundr](https://github.com/carloslack/volundr)
##### md5sum output for the modified ELF is automatically hijacked by KoviD
![elf](persist.gif?raw=true)
> KoviD must be running at the time install.sh is called so the new md5sum output can be applied to the new modified ELF.
> This is very specific for `md5sum` tool only and `md5sum -c` is not handled.

## Hide pre-defined network application
##### Network Application names are defined in `netapp.h` and must follow what is stored in fnode->filename. For example, in Ubuntu `nc` is actually `nc.traditional` : `/usr/bin/nc -> /etc/alternatives/nc -> /bin/nc.traditional`
![netapp](netapp.gif?raw=true)
> Both process and connection are hidden, as shown in the animation above.
> Because it is a `Network Application` if the module is removed the process is killed
> in order to not leave traces behind
> `netapp.h` executable names are dummy and there just as examples and should be changed to match actual NetApp tools
> one will use.

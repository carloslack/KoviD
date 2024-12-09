#!/bin/sh

# Insert the kovid module
insmod kovid.ko 2> /dev/null

# Search for 'kovid' in critical system directories
echo "Finding LKM"
find /sys /proc /etc /var -name 'kovid'

rmmod kovid

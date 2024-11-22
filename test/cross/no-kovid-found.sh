#!/bin/sh

# Insert the kovid module
insmod kovid.ko 2> /dev/null

# Search for 'kovid' in critical system directories
find /sys /proc /etc /var -name 'kovid'

# Attempt to remove the kovid module
rmmod kovid

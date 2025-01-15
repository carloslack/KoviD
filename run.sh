#!/bin/bash
# This script must be used when loading KoviD in DEPLOY mode
#
# SPACE: Adding a space before the command prevents it
# from being logged in the command history in some shells.
# Usage:
#	$<SPACE>./run.sh
#
# rm -f this file after use

echo "Killing dmesg"
sudo kill -PIPE `pgrep dmesg`

echo "Insmod"
sudo insmod ./kovid.ko

echo "Unhiding proc UI"
kill -CONT 31337

# Repeat a few times
echo "Clearing jornal"
sudo sh -c 'echo journal-flush >/proc/kv'
sleep 3
sudo sh -c 'echo journal-flush >/proc/kv'
sleep 3
sudo sh -c 'echo journal-flush >/proc/kv'

echo "Hiding proc UI"
kill -CONT 31337

echo "Checking journal"
journalctl -k

# Uncomment next line when it is for real
# rm -f $0

#!/bin/sh

insmod kovid.ko

# The kovid trick
kill -CONT 31337

# Run the a.out executable in the background
./a.out &
AOUT_PID=$!  # Capture the PID of a.out

# Wait briefly to ensure a.out has started
sleep 1

# Output the PID (for debugging or verification)
echo "PID of a.out is $AOUT_PID"

echo $AOUT_PID > /proc/myprocname

# Attempt to kill the process by PID and log the output
kill -9 "$AOUT_PID"

rmmod kovid.ko

kill -9 "$AOUT_PID"

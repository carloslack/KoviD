#!/bin/bash
set -eou pipefail
# Calculates syslog (and similar) boot timestamp
#
# Usage e.g.:
#	$ ./timestamp.sh 364.010543
#	00:06:04.010543

timestamp="$1"

# Split the timestamp into seconds and microseconds
seconds=$(echo $timestamp | cut -d. -f1)
microseconds=$(echo $timestamp | cut -d. -f2)

# Calculate hours, minutes, and remaining seconds
hours=$((seconds / 3600))
minutes=$(((seconds % 3600) / 60))
remaining_seconds=$((seconds % 60))

# Print in HH:MM:SS.microseconds format
printf "%02d:%02d:%02d.%s\n" $hours $minutes $remaining_seconds $microseconds

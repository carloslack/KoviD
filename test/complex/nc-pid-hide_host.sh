#!/bin/bash

# Define the backdoor host and port
BACKDOOR_HOST="localhost"
BACKDOOR_PORT=9999

# Function to send a command and verify that a specific string is NOT in the response
send_command_and_verify_absence() {
    local CMD=$1
    local ABSENT_STRING=$2

    echo "Sending command: $CMD"
    RESPONSE=$(echo "$CMD" | nc -w 5 "$BACKDOOR_HOST" "$BACKDOOR_PORT")
    echo "Received response: $RESPONSE"

    if echo "$RESPONSE" | grep -q "$ABSENT_STRING"; then
        echo "Command '$CMD' failed: '$ABSENT_STRING' found in the output."
        exit 1
    else
        echo "Command '$CMD' executed successfully: '$ABSENT_STRING' not found in the output."
    fi
}

# Wait briefly to ensure the backdoor is ready
sleep 5

echo "Connecting to backdoor at $BACKDOOR_HOST:$BACKDOOR_PORT..."

# Send test command to check that /bin/nc is NOT present in ps -a
send_command_and_verify_absence "ps -a" "/bin/nc"

echo "Backdoor test passed: /bin/nc is not present in the process list."

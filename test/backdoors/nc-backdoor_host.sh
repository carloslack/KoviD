#!/bin/bash
set -e

# Define the backdoor host and port
BACKDOOR_HOST="localhost"
BACKDOOR_PORT=9999

# Function to send a command and verify the response
send_command() {
    local CMD=$1
    local EXPECTED_OUTPUT=$2

    echo "Sending command: $CMD"
    RESPONSE=$(echo "$CMD" | nc -w 5 "$BACKDOOR_HOST" "$BACKDOOR_PORT")
    echo "Received response: $RESPONSE"

    if echo "$RESPONSE" | grep -q "$EXPECTED_OUTPUT"; then
        echo "Command '$CMD' executed successfully."
    else
        echo "Command '$CMD' failed or did not return expected output."
        exit 1
    fi
}

# Wait briefly to ensure the backdoor is ready
sleep 5

echo "Connecting to backdoor at $BACKDOOR_HOST:$BACKDOOR_PORT..."

# Send test command
send_command "uname -a" "Linux"

echo "Backdoor command executed successfully."

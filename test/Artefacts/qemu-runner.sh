#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Function to cleanup QEMU and temporary files on exit
cleanup() {
    echo "Cleaning up QEMU and temporary files..."
    if [[ -n "$QEMU_PID" ]]; then
        kill -SIGTERM "$QEMU_PID" 2>/dev/null || true
        wait "$QEMU_PID" 2>/dev/null || true
    fi
    if [[ -f "$TEMP_ROOTFS" ]]; then
        rm -f "$TEMP_ROOTFS"
    fi
}
trap cleanup EXIT

# Define the project root based on the script's location
PROJECT_ROOT="$(cd "$(dirname "$0")"/.. && pwd)"
CMAKE_BINARY_DIR="${PROJECT_ROOT}/build"

# Define paths for necessary files
KERNEL_IMAGE="${PROJECT_ROOT}/test/test-artefacts/linux-5.10/bzImage"
ROOT_FS="${PROJECT_ROOT}/test/test-artefacts/linux-5.10/rootfs.ext2"
TEST_DIR="${PROJECT_ROOT}/test/features"
TEST_BACKDOOR_DIR="${PROJECT_ROOT}/test/backdoors"  # Directory for backdoor tests
RFS_PATH="/root"                     
SSH_PORT=5555                         
SSH_KEY="${PROJECT_ROOT}/test/Artefacts/id_rsa_qemu" 
QEMU_FLAGS="-nographic"
KOVID_MODULE="${CMAKE_BINARY_DIR}/kovid.ko"

# Ensure SSH key has correct permissions
chmod 600 "$SSH_KEY"

# Check for essential files
if [[ ! -f "$KERNEL_IMAGE" || ! -f "$ROOT_FS" || ! -f "$KOVID_MODULE" ]]; then
    echo "Error: Essential files (bzImage, rootfs.ext2, or kovid.ko) not found."
    exit 1
fi

DEPLOY=${DEPLOY:-0}

# Export DEPLOY for use in lit
export DEPLOY

# Function to execute each test script on QEMU
# Parameters:
#   $1 - Path to the test script on the host
execute_regular_test_script() {
    local TEST_SCRIPT=$1
    local TEST_LOG="$(basename "${TEST_SCRIPT%.sh}.log")"

    # Create a writable copy of the root filesystem
    local TEMP_ROOTFS="/tmp/rootfs_writable_$(basename "$ROOT_FS")"
    cp "${ROOT_FS}" "${TEMP_ROOTFS}"

    echo "Starting QEMU in background for test: $(basename "$TEST_SCRIPT")"
    qemu-system-x86_64 \
        -kernel "$KERNEL_IMAGE" \
        -append "root=/dev/sda rw console=ttyS0,115200 init=/sbin/init" \
        -drive format=raw,file="$TEMP_ROOTFS" \
        -device e1000,netdev=net0 \
        -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22,hostfwd=tcp::9999-:9999 \
        $QEMU_FLAGS > "qemu_output_$(basename "$TEST_SCRIPT").log" 2>&1 &
    local QEMU_PID=$!

    # Wait for SSH to be available
    echo "Waiting for QEMU && SSH to be ready..."
    for i in {1..20}; do
        if ssh -i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p "${SSH_PORT}" root@localhost 'echo SSH is ready' >/dev/null 2>&1; then
            echo "SSH connection to QEMU established."
            break
        fi
        echo "QEMU && SSH not ready, retrying in 3 seconds... (Attempt $i of 20)"
        sleep 3
    done

    # Final check if SSH is still not available
    if ! ssh -i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p "${SSH_PORT}" root@localhost 'echo SSH is ready' >/dev/null 2>&1; then
        echo "Failed to establish SSH connection to QEMU after multiple attempts. Exiting..."
        kill -SIGTERM "$QEMU_PID" 2>/dev/null || true
        rm -f "$TEMP_ROOTFS"
        exit 1
    fi

    # Transfer kovid.ko to QEMU and load it
    echo "Transferring kovid.ko to QEMU..."
    scp -i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -P "${SSH_PORT}" "$KOVID_MODULE" root@localhost:"$RFS_PATH/kovid.ko" || {
        echo "Failed to transfer kovid.ko to QEMU."
        kill -SIGTERM "$QEMU_PID" 2>/dev/null || true
        rm -f "$TEMP_ROOTFS"
        exit 1
    }

    echo "Running test script $(basename "$TEST_SCRIPT") on QEMU..."

    # Transfer the test script to QEMU
    scp -i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -P "${SSH_PORT}" "$TEST_SCRIPT" root@localhost:"$RFS_PATH/$(basename "$TEST_SCRIPT")" || {
        echo "Failed to transfer test script $(basename "$TEST_SCRIPT") to QEMU."
        kill -SIGTERM "$QEMU_PID" 2>/dev/null || true
        rm -f "$TEMP_ROOTFS"
        exit 1
    }

    # Run the test script on QEMU, capturing output and returning immediately
    ssh -i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -p "${SSH_PORT}" root@localhost "nohup sh -c 'chmod +x $RFS_PATH/$(basename "$TEST_SCRIPT") && $RFS_PATH/$(basename "$TEST_SCRIPT")' > $RFS_PATH/$TEST_LOG 2>&1 &" || {
        echo "Failed to execute test script $(basename "$TEST_SCRIPT") on QEMU."
        kill -SIGTERM "$QEMU_PID" 2>/dev/null || true
        rm -f "$TEMP_ROOTFS"
        exit 1
    }

    sleep 1  # Wait briefly to ensure the test script starts

    # Retrieve the log file from QEMU
    echo "Retrieving log file $TEST_LOG from QEMU..."
    scp -i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -P "${SSH_PORT}" root@localhost:"$RFS_PATH/$TEST_LOG" . || {
        echo "Failed to retrieve log file $TEST_LOG from QEMU."
        kill -SIGTERM "$QEMU_PID" 2>/dev/null || true
        rm -f "$TEMP_ROOTFS"
        exit 1
    }

    # Display completion message
    echo "Test script $(basename "$TEST_SCRIPT") completed. Output saved to $TEST_LOG."

    # Cleanup
    echo "Cleaning up QEMU for $(basename "$TEST_SCRIPT")..."
    kill -SIGTERM "$QEMU_PID" 2>/dev/null
    wait "$QEMU_PID" 2>/dev/null || true
    rm -f "$TEMP_ROOTFS"
    echo "QEMU shut down and temporary files cleaned for $(basename "$TEST_SCRIPT")."
}

# Function to execute tests in a given directory
# Parameters:
#   $1 - Path to the test directory
execute_regular_tests() {
    local DIR=$1

    for TEST_FILE in "$DIR"/*.test; do
        local TEST_SCRIPT="${TEST_FILE%.test}.sh"

        echo "Deploy: ${DEPLOY}. Note that if DEPLOY is 1, we may mark some tests as Unsupported"

        if [[ -f "$TEST_FILE" && -f "$TEST_SCRIPT" ]]; then
            # Check for DEPLOY_ONLY and DEBUG_ONLY markers
            local DEPLOY_ONLY_MARKER=$(grep -c '^# DEPLOY_ONLY' "$TEST_FILE")
            local DEBUG_ONLY_MARKER=$(grep -c '^# DEBUG_ONLY' "$TEST_FILE")

            if [[ "$DEPLOY_ONLY_MARKER" -gt 0 && "$DEBUG_ONLY_MARKER" -gt 0 ]]; then
                echo "Skipping $(basename "$TEST_SCRIPT") because it has both DEPLOY_ONLY and DEBUG_ONLY markers."
            elif [[ "$DEPLOY_ONLY_MARKER" -gt 0 ]]; then
                if [[ "$DEPLOY" == "1" ]]; then
                    execute_regular_test_script "$TEST_SCRIPT"
                else
                    echo "Skipping $(basename "$TEST_SCRIPT") because it requires DEPLOY=1."
                fi
            elif [[ "$DEBUG_ONLY_MARKER" -gt 0 ]]; then
                if [[ "$DEPLOY" != "1" ]]; then
                    execute_regular_test_script "$TEST_SCRIPT"
                else
                    echo "Skipping $(basename "$TEST_SCRIPT") because it's a DEBUG_ONLY test and DEPLOY=1."
                fi
            else
                # No marker, run the test regardless of DEPLOY
                execute_regular_test_script "$TEST_SCRIPT"
            fi
        else
            echo "Skipping $(basename "$TEST_SCRIPT") as it or the .test file is missing."
        fi
    done
}

# Function to execute each backdoor test
# Parameters:
#   $1 - Path to the guest test script on the host
#   $2 - Path to the host test script on the host
execute_backdoor_test() {
    local GUEST_TEST_SCRIPT=$1
    local HOST_TEST_SCRIPT=$2
    local TEST_LOG_GUEST="$(basename "${GUEST_TEST_SCRIPT%.sh}.log")"
    local TEST_LOG_HOST="$(basename "${HOST_TEST_SCRIPT%.sh}.log")"

    # Create a writable copy of the root filesystem
    TEMP_ROOTFS="/tmp/rootfs_writable_$(basename "$ROOT_FS")"
    cp "${ROOT_FS}" "${TEMP_ROOTFS}"

    echo "Starting QEMU in background for backdoor test: $(basename "$GUEST_TEST_SCRIPT")"
    
    # Launch QEMU in the background and redirect output to the build directory
    qemu-system-x86_64 \
        -kernel "$KERNEL_IMAGE" \
        -append "root=/dev/sda rw console=ttyS0,115200 init=/sbin/init" \
        -drive format=raw,file="$TEMP_ROOTFS" \
        -device e1000,netdev=net0 \
        -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22,hostfwd=tcp::9999-:9999 \
        $QEMU_FLAGS > "${CMAKE_BINARY_DIR}/qemu_output_$(basename "$GUEST_TEST_SCRIPT").log" 2>&1 &
    local QEMU_PID=$!

    # Wait for SSH to become available
    echo "Waiting for SSH to be ready for backdoor test: $(basename "$GUEST_TEST_SCRIPT")..."
    for i in {1..30}; do
        if ssh -i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=5 -p "${SSH_PORT}" root@localhost 'echo SSH is ready' >/dev/null 2>&1; then
            echo "SSH connection established for backdoor test: $(basename "$GUEST_TEST_SCRIPT")."
            break
        fi
        echo "SSH not ready, retrying in 3 seconds... (Attempt $i/30)"
        sleep 3
    done

    # Final check if SSH is still not available
    if ! ssh -i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=5 -p "${SSH_PORT}" root@localhost 'echo SSH is ready' >/dev/null 2>&1; then
        echo "Failed to establish SSH connection to QEMU for backdoor test: $(basename "$GUEST_TEST_SCRIPT"). Exiting..."
        kill -SIGTERM "$QEMU_PID" 2>/dev/null || true
        rm -f "$TEMP_ROOTFS"
        exit 1
    fi

    # Copy Netcat and its libraries to the guest
    echo "Copying Netcat and its libraries to QEMU..."
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -P "${SSH_PORT}" /bin/nc.openbsd root@localhost:"/bin/nc" || {
        echo "Failed to copy Netcat to QEMU."
        kill -SIGTERM "$QEMU_PID" 2>/dev/null || true
        rm -f "$TEMP_ROOTFS"
        exit 1
    }

    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -P "${SSH_PORT}" /lib/x86_64-linux-gnu/libbsd.so.0 root@localhost:"/lib/libbsd.so.0" || {
        echo "Failed to copy libbsd.so.0 to QEMU."
        kill -SIGTERM "$QEMU_PID" 2>/dev/null || true
        rm -f "$TEMP_ROOTFS"
        exit 1
    }

    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -P "${SSH_PORT}" /lib/x86_64-linux-gnu/libmd.so.0 root@localhost:"/lib/libmd.so.0" || {
        echo "Failed to copy libmd.so.0 to QEMU."
        kill -SIGTERM "$QEMU_PID" 2>/dev/null || true
        rm -f "$TEMP_ROOTFS"
        exit 1
    }

    # Transfer and execute the guest backdoor test script
    echo "Transferring and executing guest backdoor test script: $(basename "$GUEST_TEST_SCRIPT") on QEMU..."
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -P "${SSH_PORT}" "$GUEST_TEST_SCRIPT" root@localhost:"$RFS_PATH/$(basename "$GUEST_TEST_SCRIPT")" || {
        echo "Failed to transfer guest backdoor test script: $(basename "$GUEST_TEST_SCRIPT") to QEMU."
        kill -SIGTERM "$QEMU_PID" 2>/dev/null || true
        rm -f "$TEMP_ROOTFS"
        exit 1
    }

    # Execute the guest backdoor test script in the background on QEMU
    ssh -i "$SSH_KEY" -o StrictHostKeyChecking=no -p "${SSH_PORT}" root@localhost "nohup sh -c 'chmod +x $RFS_PATH/$(basename "$GUEST_TEST_SCRIPT") && $RFS_PATH/$(basename "$GUEST_TEST_SCRIPT")' > $RFS_PATH/$TEST_LOG_GUEST 2>&1 &" || {
        echo "Failed to execute guest backdoor test script: $(basename "$GUEST_TEST_SCRIPT") on QEMU."
        kill -SIGTERM "$QEMU_PID" 2>/dev/null || true
        rm -f "$TEMP_ROOTFS"
        exit 1
    }

    sleep 4  # Wait briefly to ensure the test script starts

    # Execute the host backdoor test script
    echo "Executing host backdoor test script: $(basename "$HOST_TEST_SCRIPT")..."
    bash "$HOST_TEST_SCRIPT" > "$TEST_LOG_HOST" 2>&1

    # Retrieve the guest log file from QEMU
    echo "Retrieving log file $TEST_LOG_GUEST from QEMU..."
    scp -i "$SSH_KEY" -o StrictHostKeyChecking=no -P "${SSH_PORT}" root@localhost:"$RFS_PATH/$TEST_LOG_GUEST" "${CMAKE_BINARY_DIR}/" || {
        echo "Failed to retrieve log file $TEST_LOG_GUEST from QEMU."
    }

    # Manually kill QEMU after backdoor test
    echo "Killing QEMU after backdoor test: $(basename "$GUEST_TEST_SCRIPT")..."
    kill -SIGTERM "$QEMU_PID" 2>/dev/null || true

    # Wait for QEMU to terminate
    wait "$QEMU_PID" 2>/dev/null || true

    # Display completion messages
    echo "Backdoor test script $(basename "$GUEST_TEST_SCRIPT") completed. Output saved to $TEST_LOG_GUEST."
    echo "Host backdoor test script $(basename "$HOST_TEST_SCRIPT") completed. Output saved to $TEST_LOG_HOST."

    # Cleanup
    echo "Cleaning up temporary files for backdoor test: $(basename "$GUEST_TEST_SCRIPT")..."
    rm -f "$TEMP_ROOTFS"
    echo "Cleanup completed for backdoor test: $(basename "$GUEST_TEST_SCRIPT")."
}


# Function to execute backdoor tests in a given directory
# Parameters:
#   $1 - Path to the backdoor test directory
execute_backdoor_tests() {
    local DIR=$1

    for TEST_FILE in "$DIR"/*.test; do
        local GUEST_TEST_SCRIPT="${TEST_FILE%.test}.sh"
        local HOST_TEST_SCRIPT="${TEST_FILE%.test}_host.sh"

        echo "Deploy: ${DEPLOY}. Note that if DEPLOY is 1, we may mark some backdoor tests as Unsupported"

        if [[ -f "$TEST_FILE" && -f "$GUEST_TEST_SCRIPT" && -f "$HOST_TEST_SCRIPT" ]]; then
            # Check for DEPLOY_ONLY and DEBUG_ONLY markers
            local DEPLOY_ONLY_MARKER=$(grep -c '^# DEPLOY_ONLY' "$TEST_FILE")
            local DEBUG_ONLY_MARKER=$(grep -c '^# DEBUG_ONLY' "$TEST_FILE")

            if [[ "$DEPLOY_ONLY_MARKER" -gt 0 && "$DEBUG_ONLY_MARKER" -gt 0 ]]; then
                echo "Skipping backdoor test $(basename "$GUEST_TEST_SCRIPT") because it has both DEPLOY_ONLY and DEBUG_ONLY markers."
            elif [[ "$DEPLOY_ONLY_MARKER" -gt 0 ]]; then
                if [[ "$DEPLOY" == "1" ]]; then
                    execute_backdoor_test "$GUEST_TEST_SCRIPT" "$HOST_TEST_SCRIPT"
                else
                    echo "Skipping backdoor test $(basename "$GUEST_TEST_SCRIPT") because it requires DEPLOY=1."
                fi
            elif [[ "$DEBUG_ONLY_MARKER" -gt 0 ]]; then
                if [[ "$DEPLOY" != "1" ]]; then
                    execute_backdoor_test "$GUEST_TEST_SCRIPT" "$HOST_TEST_SCRIPT"
                else
                    echo "Skipping backdoor test $(basename "$GUEST_TEST_SCRIPT") because it's a DEBUG_ONLY test and DEPLOY=1."
                fi
            else
                # No marker, run the backdoor test regardless of DEPLOY
                execute_backdoor_test "$GUEST_TEST_SCRIPT" "$HOST_TEST_SCRIPT"
            fi
        else
            echo "Skipping backdoor test $(basename "$GUEST_TEST_SCRIPT") as it or its companion files are missing."
        fi
    done
}

# Main Execution

# Execute Regular Tests
echo "=============================="
echo "Starting Regular Tests"
echo "=============================="
execute_regular_tests "$TEST_DIR"

# Execute Backdoor Tests
echo "=============================="
echo "Starting Backdoor Tests"
echo "=============================="
execute_backdoor_tests "$TEST_BACKDOOR_DIR"

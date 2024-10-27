#!/bin/bash

# Define the project root based on the assumed structure relative to the build directory
PROJECT_ROOT="$(cd "$(dirname "$0")"/.. && pwd)"
CMAKE_BINARY_DIR="${PROJECT_ROOT}/build"

# Define paths for necessary files
KERNEL_IMAGE="${PROJECT_ROOT}/test/test-artefacts/linux-5.15/bzImage"
ROOT_FS="${PROJECT_ROOT}/test/test-artefacts/linux-5.15/rootfs.ext2"
TEST_DIR="${PROJECT_ROOT}/test/features"
RFS_PATH="/root"                     
SSH_PORT=5555                         
SSH_KEY="${PROJECT_ROOT}/test/Artefacts/id_rsa_qemu" 
QEMU_FLAGS="-nographic"
KOVID_MODULE="${CMAKE_BINARY_DIR}/kovid.ko"

# Check for essential files
if [[ ! -f "$KERNEL_IMAGE" || ! -f "$ROOT_FS" || ! -f "$KOVID_MODULE" ]]; then
    echo "Error: Essential files (bzImage, rootfs.ext2, or kovid.ko) not found."
    exit 1
fi

# Create a writable copy of the root filesystem
TEMP_ROOTFS="/tmp/rootfs_writable.ext2"
cp "${ROOT_FS}" "${TEMP_ROOTFS}"

# Cleanup function to terminate QEMU and remove temporary files
cleanup() {
    echo "Cleaning up..."
    if [[ -n "$QEMU_PID" ]]; then
        kill -SIGTERM "$QEMU_PID" 2>/dev/null
        wait "$QEMU_PID" 2>/dev/null
    fi
    rm -f "$TEMP_ROOTFS"
    echo "QEMU shut down and temporary files cleaned."
}

# Trap to ensure cleanup runs on exit
trap cleanup EXIT INT ERR

# Start QEMU in the background
qemu-system-x86_64 \
    -kernel "$KERNEL_IMAGE" \
    -append "root=/dev/sda rw console=ttyS0,115200 init=/sbin/init" \
    -drive format=raw,file="$TEMP_ROOTFS" \
    -device e1000,netdev=net0 \
    -netdev user,id=net0,hostfwd=tcp::${SSH_PORT}-:22 \
    $QEMU_FLAGS &> qemu_output.log &

QEMU_PID=$!

# Wait for SSH to be available
echo "Waiting for QEMU && SSH to be ready..."
for i in {1..20}; do
    if ssh -i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p ${SSH_PORT} root@localhost 'echo SSH is ready'; then
        echo "SSH connection to QEMU established."
        break
    fi
    echo "QEMU && SSH not ready, retrying in 3 seconds... (Attempt $i of 20)"
    sleep 3
done

# Final check if SSH is still not available
if ! ssh -i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o ConnectTimeout=5 -p ${SSH_PORT} root@localhost 'echo SSH is ready'; then
    echo "Failed to establish SSH connection to QEMU after multiple attempts. Exiting..."
    exit 1
fi

# Transfer kovid.ko to QEMU and load it
echo "Transferring and loading kovid.ko on QEMU..."
scp -i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -P ${SSH_PORT} "$KOVID_MODULE" root@localhost:"$RFS_PATH/kovid.ko" || {
    echo "Failed to transfer kovid.ko to QEMU."
    exit 1
}
ssh -i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -p ${SSH_PORT} root@localhost "insmod $RFS_PATH/kovid.ko" || {
    echo "Failed to load kovid.ko on QEMU."
    exit 1
}

# Function to execute each test script on QEMU
execute_test_script() {
    TEST_SCRIPT=$1  # Path to the test script on the host
    TEST_LOG="$(basename "${TEST_SCRIPT%.sh}.log")"  # Log file name on the host

    echo "Running test script $(basename "$TEST_SCRIPT") on QEMU..."

    # Transfer the test script to QEMU
    scp -i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -P ${SSH_PORT} "$TEST_SCRIPT" root@localhost:"$RFS_PATH/$(basename "$TEST_SCRIPT")" || {
        echo "Failed to transfer test script $(basename "$TEST_SCRIPT") to QEMU."
        exit 1
    }

    # Run the test script on QEMU in the background, capturing output and returning immediately
    ssh -i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -p ${SSH_PORT} root@localhost "nohup sh -c 'chmod +x $RFS_PATH/$(basename "$TEST_SCRIPT") && $RFS_PATH/$(basename "$TEST_SCRIPT")' > $RFS_PATH/$TEST_LOG 2>&1 &" || {
        echo "Failed to execute test script $(basename "$TEST_SCRIPT") on QEMU."
        exit 1
    }

    # Wait a brief moment to ensure command starts
    sleep 1

    # Retrieve the log file from QEMU
    scp -i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -P ${SSH_PORT} root@localhost:"$RFS_PATH/$TEST_LOG" . || {
        echo "Failed to retrieve log file $TEST_LOG from QEMU."
        exit 1
    }

    # Ensure the completion message is displayed
    echo "Test script $(basename "$TEST_SCRIPT") completed. Output saved to $TEST_LOG."
}

# Loop through each .test file and corresponding script in TEST_DIR
for TEST_FILE in "$TEST_DIR"/*.test; do
    TEST_SCRIPT="${TEST_FILE%.test}.sh"
    # Ensure both .test and .sh files exist before running the test
    if [[ -f "$TEST_FILE" && -f "$TEST_SCRIPT" ]]; then
        execute_test_script "$TEST_SCRIPT"
    else
        echo "Skipping $(basename "$TEST_SCRIPT") as it or the .test file is missing."
    fi
done

# After all tests are done, shut down QEMU
cleanup

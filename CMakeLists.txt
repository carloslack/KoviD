cmake_minimum_required(VERSION 3.10)
project(kovid)

# Step 1: Define Kernel Version Variable
execute_process(
    COMMAND uname -r
    OUTPUT_VARIABLE CURRENT_KERNEL_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
set(KOVID_LINUX_VERSION "${CURRENT_KERNEL_VERSION}" CACHE STRING "Linux kernel version to build against")
message("-- Linux Target: ${KOVID_LINUX_VERSION}")

# Step 2: Allow user to specify the kernel directory
set(KERNEL_DIR "/lib/modules/${KOVID_LINUX_VERSION}/build" CACHE PATH "Path to the kernel source or headers for version ${KOVID_LINUX_VERSION}")

# Step 3: Check for Kernel Headers
if(NOT EXISTS "${KERNEL_DIR}")
    message(FATAL_ERROR "Kernel headers for version ${KOVID_LINUX_VERSION} not found in ${KERNEL_DIR}")
endif()
message("-- Linux Headers: ${KERNEL_DIR}")

# Step 4: Find Necessary Programs
find_program(LD ld)
find_program(AS as)
find_program(CTAGS ctags)
find_program(JOURNALCTL journalctl)
find_program(UUIDGEN uuidgen)

set(CMAKE_C_COMPILER "gcc")

set(KOVID_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

# Step 5: Get UUID
execute_process(
    COMMAND ${UUIDGEN}
    OUTPUT_VARIABLE UUIDGEN_OUTPUT
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

# Step 6: Define Build Options
option(DEPLOY "Build in Deploy mode" OFF)
option(DEBUG "Build in Debug mode " OFF)

if(NOT DEPLOY)
    set(DEBUG_PR -DDEBUG_RING_BUFFER)
    set(DEBUG ON CACHE BOOL "Build in Debug mode" FORCE)
endif()

# Cross tests are the ones we run on qemu.
# It needs both KOVID_LINUX and KERNEL_DIR to be setup
# since we support linux 5.10 only for this kind of tests.
option(CROSS_TESTS "Turn ON cross tests on qemu" OFF)

option(NATIVE_TESTS "Turn ON native tests" ON)

# Check if KOVID_LINUX and KERNEL_DIR variables are set
if(DEFINED KOVID_LINUX AND "${KOVID_LINUX}" STREQUAL "5.10" AND DEFINED KERNEL_DIR AND NOT "${KERNEL_DIR}" STREQUAL "")
    set(CROSS_TESTS ON CACHE BOOL "Turn ON cross tests on qemu" FORCE)
    set(NATIVE_TESTS ON CACHE BOOL "Turn OFF native tests" FORCE)
endif()

# Print status messages to verify settings
message(STATUS "KOVID_LINUX: ${KOVID_LINUX}")
message(STATUS "KERNEL_DIR: ${KERNEL_DIR}")
message(STATUS "CROSS_TESTS: ${CROSS_TESTS}")
message(STATUS "NATIVE_TESTS: ${NATIVE_TESTS}")

message(STATUS "DEPLOY build: ${DEPLOY}")
message(STATUS "DEBUG build: ${DEBUG}")

# Step 7: Create the 'kovid' Target
add_custom_target(kovid ALL
    COMMAND echo "-- We use CMake for tests only - kovid.ko is being built from Makefile in the root folder"
    COMMENT "Building kovid kernel module"
)

# Step 8: Handle Cleaning
add_custom_target(clean-kovid
    COMMAND make -C "${KERNEL_DIR}" M="${CMAKE_CURRENT_SOURCE_DIR}" clean
    COMMAND ${CMAKE_COMMAND} -E rm -f ${CMAKE_CURRENT_BINARY_DIR}/persist ${CMAKE_CURRENT_BINARY_DIR}/persist.o ${CMAKE_CURRENT_BINARY_DIR}/persist.S
    COMMENT "Cleaning kovid module"
)

# Step 9: Copy kovid.ko and qemu-runner.sh to the build directory
add_custom_command(TARGET kovid POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/kovid.ko ${CMAKE_CURRENT_BINARY_DIR}/kovid.ko
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/test/Artefacts/qemu-runner.sh ${CMAKE_CURRENT_BINARY_DIR}/qemu-runner.sh
    COMMENT "Copying kovid.ko and qemu-runner.sh to build directory"
)

add_subdirectory(test)

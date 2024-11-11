find_package(LLVM REQUIRED CONFIG)

message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

include(AddLLVM)

# Find the paths to FileCheck and not
find_program(FILECHECK_EXE FileCheck-18)
find_program(NOT_EXE not-18)

if(NOT FILECHECK_EXE)
    message(FATAL_ERROR "FileCheck executable not found!")
endif()

if(NOT NOT_EXE)
    message(FATAL_ERROR "'not' executable not found!")
endif()

# Pass the paths to lit via configure_file
set(FILECHECK_PATH "${FILECHECK_EXE}")
set(NOT_PATH "${NOT_EXE}")

configure_lit_site_cfg(
        ${CMAKE_CURRENT_SOURCE_DIR}/lit.site.cfg.py.in
        ${CMAKE_CURRENT_BINARY_DIR}/lit.site.cfg.py
        MAIN_CONFIG
        ${CMAKE_CURRENT_SOURCE_DIR}/lit.cfg.py
)

option(DEPLOY "Turn off ring buffer debug" OFF)

# Define a custom target to run qemu-runner.sh before tests
add_custom_target(run-qemu-runner
    COMMAND DEPLOY=${DEPLOY} bash ${CMAKE_BINARY_DIR}/qemu-runner.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    COMMENT "Running qemu-runner.sh"
)

add_lit_testsuite(check-kovid "Running the KOVID regression tests"
        ${CMAKE_CURRENT_BINARY_DIR}
        DEPENDS ${KOVID_TEST_DEPENDS} run-qemu-runner
        )
set_target_properties(check-kovid PROPERTIES FOLDER "Tests")

add_lit_testsuites(KOVID ${CMAKE_CURRENT_SOURCE_DIR} DEPENDS ${KOVID_TEST_DEPENDS})

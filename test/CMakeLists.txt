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

# Find llvm-lit
find_program(LLVM_LIT NAMES llvm-lit lit PATHS "${LLVM_TOOLS_BINARY_DIR}" "${LLVM_BUILD_BINARY_DIR}" "/usr/bin" NO_DEFAULT_PATH)

if(NOT LLVM_LIT)
    message(FATAL_ERROR "llvm-lit not found. Please install it or specify its location.")
else()
    message(STATUS "Found llvm-lit: ${LLVM_LIT}")
endif()

# Check and set LLVM_EXTERNAL_LIT
if(DEFINED LLVM_EXTERNAL_LIT AND EXISTS ${LLVM_EXTERNAL_LIT})
    message(STATUS "Using LLVM_EXTERNAL_LIT: ${LLVM_EXTERNAL_LIT}")
else()
    message(WARNING "LLVM_EXTERNAL_LIT not set or invalid, using LLVM_LIT instead")
    set(LLVM_EXTERNAL_LIT ${LLVM_LIT} CACHE FILEPATH "Path to llvm-lit" FORCE)
endif()

# Define the custom target if CROSS_TESTS is ON
if(CROSS_TESTS)
    add_custom_target(run-qemu-runner
        COMMAND DEPLOY=${DEPLOY} bash ${CMAKE_BINARY_DIR}/qemu-runner.sh
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        COMMENT "Running qemu-runner.sh"
    )

    add_lit_testsuite(check-kovid "Running the KOVID regression tests"
        ${CMAKE_CURRENT_BINARY_DIR}
        DEPENDS ${KOVID_TEST_DEPENDS} run-qemu-runner
    )
else()
    add_lit_testsuite(check-kovid "Running the KOVID regression tests"
        ${CMAKE_CURRENT_BINARY_DIR}
        DEPENDS ${KOVID_TEST_DEPENDS}
        ARGS --threads=1
    )
endif()

set_target_properties(check-kovid PROPERTIES FOLDER "Tests")

# Add the main lit testsuites
add_lit_testsuites(KOVID ${CMAKE_CURRENT_SOURCE_DIR} DEPENDS ${KOVID_TEST_DEPENDS})

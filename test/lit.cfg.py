# -*- Python -*-

import os
import platform
import re
import subprocess
import tempfile

import lit.formats
import lit.util

from lit.llvm import llvm_config
from lit.llvm.subst import ToolSubst
from lit.llvm.subst import FindTool

# Configuration file for the 'lit' test runner.

# name: The name of this test suite.
config.name = "KOVID"

config.test_format = lit.formats.ShTest(not llvm_config.use_lit_shell)

# suffixes: A list of file extensions to treat as test files.
config.suffixes = [".c", ".test"]

# test_source_root: The root path where tests are located.
config.test_source_root = os.path.dirname(__file__)

# test_exec_root: The root path where tests should be run.
config.test_exec_root = os.path.join(config.kovid_obj_root, "test")

config.substitutions.append(("%PATH%", config.environment["PATH"]))

llvm_config.with_system_environment(["HOME", "INCLUDE", "LIB", "TMP", "TEMP"])

# excludes: A list of directories to exclude from the testsuite. The 'Inputs'
# subdirectories contain auxiliary inputs for various tests in their parent
# directories.
config.excludes = ["Inputs", "Examples", "CMakeLists.txt", "README.txt", "LICENSE.txt", "Artefacts", "test-artefacts"]

# test_exec_root: The root path where tests should be run.
config.test_exec_root = os.path.join(config.kovid_obj_root, "test")

# Get the paths from the site configuration
filecheck_path = getattr(config, 'filecheck_path', 'FileCheck-18')
not_path = getattr(config, 'not_path', 'not-18')

# Add substitutions
config.substitutions.append(('%FileCheck-18', filecheck_path))
config.substitutions.append(('%not-18', not_path))
config.substitutions.append(("%kovid_testdir", config.kovid_obj_root))

if config.deploy_tests == '1':
    config.available_features.add('DEPLOY_ONLY')
else:
    config.available_features.add('DEBUG_ONLY')

if config.cross_tests == 'ON':
    config.available_features.add('CROSS_TESTS')

if config.native_tests == 'ON':
    config.available_features.add('NATIVE_TESTS')

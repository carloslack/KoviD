# Changelog

All notable changes to KoviD will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

## Unreleased

### Added
- Prevent ftrace from being disabled
- Added -n option to rename a hidden process on-the-fly
- -S option to list ALL processes in debug mode (useful for -n option)
- Don't show rk name in files from /proc, /sys and /var/log when using dmesg, cat, tail etc.
- If banned words are logged, replace by a newline

### Changed
- Stricter proc interface (root only) when built in release mode
- The way random magic name is generated, simplified

### Fixed
- Make sure to remove SSL socket file when KoviD in unloaded
- Memory leak from random strings


## 2.0.0 - Oct 2 2024
### Added
- Zero `/proc/sys/kernel/tainted`
- Added "-g" proc interface to support inode hiding files globally
- Added cheatsheet docfile for KoviD user interface

### Changed
- Remove magic word from syslog output, use KoviD /proc interface instead.
- Add syslog-style timestamp to `tty` logfile
- Modified "-a" proc interface to support full-path file hiding
- Set persistence filenames from uuidgen output

### Fixed
- [Fix hidden process leftover in /proc](https://github.com/carloslack/KoviD/issues/100)
- Hide kovid /proc interface even when it is available
- Fix pr(info/warn/...) to proper no-op when in release mode




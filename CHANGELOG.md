# Changelog

All notable changes to KoviD will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

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




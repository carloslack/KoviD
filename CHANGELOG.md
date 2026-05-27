# Changelog

All notable changes to KoviD will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]
### Fixed
- Fix `this_mod->state` being overridden in `do_init_module`

### Added
- Stealth: add `mod_tree` hiding

## v4.0.3
### Fixed
- Fix build regression regarding kernel 6.14
- Fix use-after-free in NF hooks: always `kmemdup` iph/tcph since skb is freed after `NF_DROP`
- Fix `GFP_KERNEL` allocations in softirq/interrupt context (NF hook path), use `GFP_ATOMIC`
- Fix concurrent access to `iph_node` list with `spin_lock_bh` + dedup check
- Fix zero-initialize `file_path` to avoid invalid `path_put` on early exit

## v4.0.2
### Added
- Full computing of hidden files sizes when passing via `sys_statfs`

## v4.0.1
### Fixed
- Fix `dmesg` (and others) gap created when hiding magic words

## v4.0.0
### Fixed
- Fix improper exit handling on connection termination (Ctrl+X)
- Fix `openssl` back-door timing kernel crash
- Fix `printk` debug leak in `DEPLOY` mode
- proc UI fix kernel crash related to PROCNAME
- Fix issue with proc UI visibility

### Changed
- Stealth: remove hard-coded names from hide list
- proc: Raise buffer size limit to match kernel's limit of 4k
- In DEPLOY `-f` is now needed for `rmmod`: `rmmod -f kovid`
- Make all hidden files and directories harder to find & access
- Back-door use random & variable length lognames
- Add support for renaming any running task

### Added
- Linux kernel `v6.x` support
- Feature: `ebpf` tool for `HTTPS` ssl strip to plain text
- Feature: proc UI commands can now return a status
- Feature: KoviD initial `gcc` code obfuscation
- Feature: signal support with new commands `signal-task-stop`, `signal-task-cont` and `signal-task-kill`
- Feature: back-door connections now hidden from `ss` and friends
- Feature: Encryption in-memory for back-door and unhide LKM keys

## v3.0.0
### Fixed
- test: False positive for `BUG: unable to handle page fault` related to `llvm.lit` test runner

### Changed
- protect, with encryption, memory stored back-door Key
- proc UI re-designed
- black-list proc UI from directory stats

### Added
- Feature: tamper stat's counter (`Links:`) for hidden hard-links
- Feature: basic encryption
- Tools: x86-64 lkm loader under `inject/`
- Tests: `ftrace`, back-doors, `proc`, `Kaudit`
- Tests: KoviD initial regression tests: back-doors, hide processes, module
- Tests:`cmake` build system for tests framework
- Tests: Native tests

## 2.1.1
### Fixed
-  Bug: back-doors deinit

## 2.1.0
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

## 2.0.0
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




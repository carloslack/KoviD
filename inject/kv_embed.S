#   BSD 3-Clause License
#
#   Copyright (c) 2024, Carlos Carvalho
#   All rights reserved.
#
#   Redistribution and use in source and binary forms, with or without
#   modification, are permitted provided that the following conditions are met:
#
#   1. Redistributions of source code must retain the above copyright notice, this
#      list of conditions and the following disclaimer.
#
#   2. Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
#   3. Neither the name of the copyright holder nor the names of its
#      contributors may be used to endorse or promote products derived from
#      this software without specific prior written permission.
#
#   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
#   AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
#   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
#   FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#   DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
#   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
#   CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
#   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#   © 2022 GitHub, Inc.
#   Terms
#   Privacy
#   Security


# mmap and load KoviD binary from .inc file

.section .data
    empty_str:      .asciz "" # pass empty name to init_module so to avoid a warning

.section .text
.globl _start

_start:
    # module size
    mov $kovid_ko_end-kovid_ko, %r15

    add $4095, %r15
    and $-4096, %r15

    mov $9, %rax                                    # mmap syscall number
    xor %rdi, %rdi                                  # addr = NULL (let kernel choose)
    mov %r15, %rsi                                  # length = rounded up module size
    mov $3, %rdx                                    # prot = PROT_READ | PROT_WRITE  0x3
    mov $0x22, %r10                                 # flags = MAP_PRIVATE | MAP_ANONYMOUS
    mov $-1, %r8                                    # fd = -1 (anonymous mapping)
    xor %r9, %r9                                    # offset 0
    syscall

    cmp $-1, %rax
    je mmap_error

    mov %rax, %r12                                  # mmap addr

    lea kovid_ko(%rip), %rsi                        # src
    mov %r12, %rdi                                  # dst
    mov $kovid_ko_end-kovid_ko, %rcx                # module size
    rep movsb

    mov $175, %rax                                  # init_module syscall number
    mov %r12, %rdi                                  # module data
    mov $kovid_ko_end-kovid_ko, %rsi                # length of the module
    lea empty_str(%rip), %rdx                       # empty string as modname
    syscall

    cmp $0, %rax
    jne init_error

    mov $11, %rax                                   # munmap syscall number
    mov %r12, %rdi                                  # address
    mov %r15, %rsi                                  # length
    syscall

    mov $60, %rax                                   # exit
    xor %rdi, %rdi                                  # zero status
    syscall

mmap_error:
    mov $60, %rax                                   # exit
    mov $1, %rdi                                    # status 1
    syscall

init_error:
    mov $11, %rax                                   # munmap syscall number
    mov %r12, %rdi                                  # address
    mov %r15, %rsi                                  # length
    syscall

    mov $60, %rax                                   # exit syscall number
    mov $1, %rdi                                    # status 1
    syscall

.section .data
kovid_ko:
    .include "kv_embed.inc"

kovid_ko_end:


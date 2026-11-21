# Project-owned PE32+ fixture. Assemble from this directory with MinGW-w64
# GCC 16.2.0 and GNU ld 2.47.20260726 (timestamps disabled for a stable hash).
# x86_64-w64-mingw32-gcc -nostdlib -s -Wl,--no-insert-timestamp,--entry,start,--image-base,0x140000000 -o triage.pe triage.s -lkernel32
.text
.globl start
start:
    subq $40, %rsp
    leaq message(%rip), %rcx
    call *__imp_OutputDebugStringA(%rip)
    addq $40, %rsp
    ret

.section .rdata,"dr"
message:
    .asciz "sleuthre triage fixture"
.balign 4
    .long 0x00000000, 0x77073096, 0xee0e612c, 0x990951ba

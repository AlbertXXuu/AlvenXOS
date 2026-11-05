    .option norelax
    .section .text, "ax"
    .global _start
_start:
    li t0, 0x80200000
    ld t1, 0(t0)
    # Reaching exit means supervisor memory was incorrectly exposed.
    li a0, 99
    li a7, 93
    ecall
1:  j 1b

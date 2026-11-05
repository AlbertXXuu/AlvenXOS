    .option norelax
    .section .text, "ax"
    .global _start
_start:
    addi t0, sp, -16
    li t1, 0x00008067
    sw t1, 0(t0)
    fence.i
    jalr ra, 0(t0)
    li a0, 99
    li a7, 93
    ecall
1:  j 1b

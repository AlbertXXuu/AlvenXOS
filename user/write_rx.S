    .option norelax
    .section .text, "ax"
    .global _start
_start:
    li t0, 0x10000
    sw zero, 0(t0)
    li a0, 99
    li a7, 93
    ecall
1:  j 1b

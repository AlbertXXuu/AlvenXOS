    .option norelax
    .section .text, "ax"
    .global _start
_start:
    mv s0, a0
    li s1, 0x6a6a
    li gp, 0x1234
    li tp, 0x5678
    addi sp, sp, -16
    sd s1, 0(sp)
1:
    li a7, 124
    ecall
    bnez a0, failed
    li t0, 0x1234
    bne gp, t0, failed
    li t0, 0x5678
    bne tp, t0, failed
    ld t0, 0(sp)
    bne t0, s1, failed
    addi s0, s0, -1
    bnez s0, 1b
    li a7, 172
    ecall
    addi a0, a0, 50
    j done
failed:
    li a0, 99
done:
    li a7, 93
    ecall
2:  j 2b

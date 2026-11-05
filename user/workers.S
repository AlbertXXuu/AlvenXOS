    .option norelax
    .section .rodata, "a"
message_a: .ascii "USER worker=A state=valid\n"
message_a_end:
message_b: .ascii "USER worker=B state=valid\n"
message_b_end:
    .equ message_length, message_a_end-message_a
    .section .text, "ax"
    .global _start
_start:
    # a0 is the documented bootstrap argument: 1 or 2, not Linux argc.
    mv s0, a0
    li gp, 0x3333
    li tp, 0x4444
    li s1, 0x1111
    li s2, 0x2222
    li s3, 0x5555
    li s4, 0x6666
    li s5, 0x7777
    li s6, 0x8888
    li s7, 0x9999
    li s8, 0xaaaa
    li s9, 0xbbbb
    li s10, 0xcccc
    li s11, 0xdddd
    addi sp, sp, -16
    sd s0, 0(sp)
    lla t0, private_word
    ld t1, 0(t0)
    bnez t1, failed
    sd s0, 0(t0)
    # No yield in this long loop: only timer preemption can interleave it.
    li t2, 700000
1:
    ld t1, 0(t0)
    bne t1, s0, failed
    addi t2, t2, -1
    bnez t2, 1b
    li a7, 124
    ecall
    li t0, 0x3333
    bne gp, t0, failed
    li t0, 0x4444
    bne tp, t0, failed
    li t0, 0x1111
    bne s1, t0, failed
    li t0, 0x2222
    bne s2, t0, failed
    li t0, 0x5555
    bne s3, t0, failed
    li t0, 0x6666
    bne s4, t0, failed
    li t0, 0x7777
    bne s5, t0, failed
    li t0, 0x8888
    bne s6, t0, failed
    li t0, 0x9999
    bne s7, t0, failed
    li t0, 0xaaaa
    bne s8, t0, failed
    li t0, 0xbbbb
    bne s9, t0, failed
    li t0, 0xcccc
    bne s10, t0, failed
    li t0, 0xdddd
    bne s11, t0, failed
    ld t0, 0(sp)
    bne t0, s0, failed
    lla t0, private_word
    ld t1, 0(t0)
    bne t1, s0, failed
    li a7, 9999
    ecall
    li t0, -38
    bne a0, t0, failed
    li a7, 172
    ecall
    bne a0, s0, failed
    li a0, 1
    li t0, 1
    beq s0, t0, worker_a
    lla a1, message_b
    li a2, message_length
    j output
worker_a:
    lla a1, message_a
    li a2, message_length
output:
    li a7, 64
    ecall
    li t0, message_length
    bne a0, t0, failed
    li a0, 37
    li t0, 1
    beq s0, t0, finish
    li a0, 41
finish:
    li a7, 93
    ecall
failed:
    li a0, 99
    li a7, 93
    ecall
2:  j 2b
    .section .bss, "aw", @nobits
    .balign 8
private_word: .space 8

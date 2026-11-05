    .option norelax
    .section .rodata
message:
    .ascii "ALVENX_DISK_A_REAL_WRITE\n"
message_end:
    .equ MESSAGE_LEN, message_end-message
    .section .text, "ax"
    .global _start
_start:
    la t0, private_word
    ld t1, 0(t0)
    bnez t1, failed
    li t1, 0x123456
    sd t1, 0(t0)
    ld t2, 0(t0)
    bne t1, t2, failed
    li a0, 1
    la a1, message
    li a2, MESSAGE_LEN
    li a7, 64
    ecall
    li t0, MESSAGE_LEN
    bne a0, t0, failed
    li a0, 71
    j done
failed:
    li a0, 99
done:
    li a7, 93
    ecall
1:  j 1b
    .section .bss
    .balign 8
private_word:
    .skip 8

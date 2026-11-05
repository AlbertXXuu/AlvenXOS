    .option norelax
    .section .text, "ax"
    .global _start
_start:
    li a0, 1
    li a1, 0x80200000
    li a2, 8
    li a7, 64
    ecall
    li t0, -14
    bne a0, t0, failed
    # Cross a mapped stack page into an unmapped page: atomic EFAULT.
    li a0, 1
    li a1, 0x3ffffffc
    li a2, 8
    li a7, 64
    ecall
    li t0, -14
    bne a0, t0, failed
    li a0, 43
    j done
failed:
    li a0, 99
done:
    li a7, 93
    ecall
1:  j 1b

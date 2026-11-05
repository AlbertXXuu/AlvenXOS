    .option norelax
    .equ BUF, 0x20000
    .equ CROSS, 0x3fffefe0
    .macro read_at ptr, count
        li a0, 3
        li a1, \ptr
        li a2, \count
        li a7, 63
        ecall
    .endm
    .macro check value
        li t0, \value
        bne a0, t0, failed
    .endm
    .macro fill ptr, count
        li t0, \ptr
        li t1, \count
        li t2, 0xa5
1:      sb t2, 0(t0)
        addi t0,t0,1
        addi t1,t1,-1
        bnez t1,1b
    .endm
    .macro unchanged ptr,count
        li t0, \ptr
        li t1, \count
        li t2, 0xa5
1:      lbu t3,0(t0)
        bne t2,t3,failed
        addi t0,t0,1
        addi t1,t1,-1
        bnez t1,1b
    .endm
    .macro output ptr,count
        li a0,1
        li a1,\ptr
        li a2,\count
        li a7,64
        ecall
        check \count
    .endm
    .text
    .global _start
_start:
    fill BUF,4096
    li a0,9
    li a1,BUF
    li a2,16
    li a7,63
    ecall
    check -9
    li a0,9
    li a7,57
    ecall
    check -9
    read_at -1,0
    check 0
    read_at BUF,1025
    check -22
    read_at 0x10000,16
    check -14
    read_at 0x80200000,16
    check -14
    read_at 0x30000,16
    check -14
    read_at BUF+4096-8,16
    check -14
    read_at -8,16
    check -14
    unchanged BUF,4096
    read_at BUF,13
    li t0,-5
    bne a0,t0,first_complete
    unchanged BUF,4096
    read_at BUF,13
first_complete:
    check 13
    li t0,BUF
    lbu s6,0(t0)  # User chooses explicit close or exit cleanup from actual data.
    output BUF,13
    read_at BUF,1000
    check 1000
    output BUF,1000
    fill CROSS,1024
    read_at CROSS,1024
    check 1024
    output CROSS,1024
    fill BUF,1024
    read_at BUF,1024
    check 268
    unchanged BUF+268,756
    output BUF,268
    read_at BUF,1024
    check 0
    read_at BUF,1024
    check 0
    read_at 0x10000,0
    check 0
    bnez s6,done
    li a0,3
    li a7,57
    ecall
    check 0
    li a0,3
    li a7,57
    ecall
    check -9
    read_at BUF,1
    check -9
    read_at -1,0
    check -9
done:
    li a0,91
    j exit
failed:
    li a0,101
exit:
    li a7,93
    ecall
1:  j 1b
    .bss
    .balign 4096
buffer:
    .skip 4096

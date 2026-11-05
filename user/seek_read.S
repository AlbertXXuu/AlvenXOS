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
    fill BUF,64
    read_at BUF,1
    li t0,-5
    bne a0,t0,first
    unchanged BUF,64
    read_at BUF,1
first:
    check 1
    li t0,BUF
    lbu s6,0(t0)
    output BUF,1
    fill BUF,64
    li a0,3
    li a1,100
    li a2,0
    li a7,62
    ecall
    check 100
    unchanged BUF,64
    fill BUF,64
    read_at BUF,17
    check 17
    output BUF,17
    fill BUF,64
    li a0,3
    li a1,-10
    li a2,1
    li a7,62
    ecall
    check 107
    unchanged BUF,64
    fill BUF,64
    read_at BUF,9
    check 9
    output BUF,9
    fill BUF,64
    li a0,3
    li a1,-5
    li a2,2
    li a7,62
    ecall
    check 2300
    unchanged BUF,64
    fill BUF,64
    read_at BUF,16
    check 5
    output BUF,5
    fill BUF,64
    li a0,3
    li a1,10
    li a2,2
    li a7,62
    ecall
    check 2315
    unchanged BUF,64
    fill BUF,64
    read_at BUF,8
    check 0
    unchanged BUF,64
    fill BUF,64
    li a0,3
    li a1,-2315
    li a2,1
    li a7,62
    ecall
    check 0
    unchanged BUF,64
    fill BUF,64
    read_at BUF,13
    check 13
    output BUF,13
    fill BUF,64
    li a0,3
    li a1,-1
    li a2,0
    li a7,62
    ecall
    check -22
    unchanged BUF,64
    fill BUF,64
    li a0,3
    li a1,0
    li a2,3
    li a7,62
    ecall
    check -22
    unchanged BUF,64
    fill BUF,64
    li a0,3
    li a1,-100
    li a2,1
    li a7,62
    ecall
    check -22
    unchanged BUF,64
    fill BUF,64
    li a0,3
    li a1,-9223372036854775808
    li a2,0
    li a7,62
    ecall
    check -22
    unchanged BUF,64
    fill BUF,64
    li a0,3
    li a1,-2306
    li a2,2
    li a7,62
    ecall
    check -22
    unchanged BUF,64
    fill BUF,64
    li a0,3
    li a1,9223372036854775807
    li a2,0
    li a7,62
    ecall
    check 9223372036854775807
    unchanged BUF,64
    fill BUF,64
    li a0,3
    li a1,1
    li a2,1
    li a7,62
    ecall
    check -75
    unchanged BUF,64
    fill BUF,64
    li a0,3
    li a1,9223372036854775807
    li a2,2
    li a7,62
    ecall
    check -75
    unchanged BUF,64
    fill BUF,64
    read_at BUF,8
    check 0
    unchanged BUF,64
    fill BUF,64
    li a0,3
    li a1,-9223372036854775807
    li a2,1
    li a7,62
    ecall
    check 0
    unchanged BUF,64
    fill BUF,64
    li a0,9
    li a1,0
    li a2,0
    li a7,62
    ecall
    check -9
    unchanged BUF,64
    fill BUF,64
    li a0,3
    li a1,512
    li a2,0
    li a7,62
    ecall
    check 512
    unchanged BUF,64
    fill BUF,64
    read_at BUF,23
    check 23
    output BUF,23
    fill BUF,64
    li a0,3
    li a1,-23
    li a2,1
    li a7,62
    ecall
    check 512
    unchanged BUF,64
    fill BUF,64
    read_at BUF,23
    check 23
    output BUF,23
    fill BUF,64
    li a0,3
    li a1,0
    li a2,2
    li a7,62
    ecall
    check 2305
    unchanged BUF,64
    fill BUF,64
    read_at BUF,1
    check 0
    unchanged BUF,64
    fill BUF,64
    li a0,3
    li a1,0
    li a2,0
    li a7,62
    ecall
    check 0
    unchanged BUF,64
    fill BUF,64
    li a0,3
    li a1,1
    li a2,1
    li a7,62
    ecall
    check 1
    unchanged BUF,64
    fill BUF,64
    read_at BUF,7
    check 7
    output BUF,7
    fill BUF,64
    li a0,3
    li a1,0
    li a2,0
    li a7,62
    ecall
    check 0
    unchanged BUF,64
    fill BUF,64
    read_at BUF,1
    check 1
    output BUF,1
    bnez s6,done
    li a0,3
    li a7,57
    ecall
    check 0
    li a0,3
    li a1,0
    li a2,0
    li a7,62
    ecall
    check -9
done:
    li a0,92
    j exit
failed:
    li a0,102
exit:
    li a7,93
    ecall
1:  j 1b
    .bss
    .balign 4096
buffer:
    .skip 4096

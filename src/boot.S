    .section .text.entry, "ax"
    .global _start
    .option norelax
_start:
    csrw sie, zero
    csrw sscratch, zero
    bnez a0, .Lsecondary
    la t0, sbss
    la t1, ebss
.Lzero:
    bgeu t0, t1, .Lready
    sd zero, 0(t0)
    addi t0, t0, 8
    j .Lzero
.Lready:
    la gp, __global_pointer$
    la sp, boot_stack_top
    call kernel_main
.Lsecondary:
    wfi
    j .Lsecondary

    .section .bss.boot_stack, "aw", @nobits
    .balign 4096
    .space 32768
boot_stack_top:

    .section .bss.trap_stack, "aw", @nobits
    .balign 4096
    .space 32768
    .global trap_stack_top
trap_stack_top:

OUTPUT_ARCH(riscv)
ENTRY(_start)
SECTIONS {
    . = 0x80200000;
    .text : ALIGN(4096) {
        text_start = .; KEEP(*(.text.entry)) *(.text .text.*)
        . = ALIGN(4096); text_end = .;
    }
    .rodata : ALIGN(4096) {
        rodata_start = .; *(.rodata .rodata.*)
        . = ALIGN(4096); rodata_end = .;
    }
    .data : ALIGN(4096) { data_start = .; *(.data .data.*) *(.sdata .sdata.*) }
    PROVIDE(__global_pointer$ = . + 0x800);
    .bss (NOLOAD) : ALIGN(4096) {
        sbss = .; *(.bss .bss.*) *(.sbss .sbss.*) *(COMMON)
        ebss = ALIGN(8);
    }
    . = ALIGN(4096);
    kernel_end = .;
    ASSERT(kernel_end < 0x80400000, "stage02 kernel must fit in first kernel 2 MiB window")
    /DISCARD/ : { *(.eh_frame .eh_frame.*) }
}

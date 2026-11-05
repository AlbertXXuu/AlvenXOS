OUTPUT_ARCH(riscv)
ENTRY(_start)
PHDRS {
    code PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
}
SECTIONS {
    . = 0x10000;
    .text : { *(.text .text.*) *(.rodata .rodata.*) } :code
    . = 0x20000;
    .data : { *(.data .data.*) } :data
    .bss : { *(.bss .bss.*) } :data
    /DISCARD/ : { *(.eh_frame*) *(.comment) }
}

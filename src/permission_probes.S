    .option norelax
    .section .text.probes, "ax"
    .balign 4
    .global probe_text_target
probe_text_target:
    .word 0x00008067

    .global probe_write_text, probe_write_text_site, probe_write_text_resume
probe_write_text:
    la t0, probe_text_target
probe_write_text_site:
    sw zero, 0(t0)
probe_write_text_resume:
    ret

    .global probe_write_rodata, probe_write_rodata_site, probe_write_rodata_resume
probe_write_rodata:
    la t0, probe_rodata_target
probe_write_rodata_site:
    sw zero, 0(t0)
probe_write_rodata_resume:
    ret

    .global probe_execute_data, probe_execute_data_resume
probe_execute_data:
    la t0, probe_data_target
    # Preserve the Rust caller's ra: this is a tail jump, not a call.
    jr t0
probe_execute_data_resume:
    ret

    .section .rodata.probes, "a"
    .balign 4
    .global probe_rodata_target
probe_rodata_target:
    .word 0x13572468

    .section .data.probes, "aw"
    .balign 4
    .global probe_data_target
probe_data_target:
    .word 0x00008067

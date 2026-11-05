use crate::{TrapFrame, memory};

struct Expected {
    cause: usize,
    pc: usize,
    address: usize,
    resume: usize,
    observed: bool,
}
static mut EXPECTED: Expected = Expected {
    cause: 0,
    pc: 0,
    address: 0,
    resume: 0,
    observed: false,
};
static mut SAVED: TrapFrame = TrapFrame::empty();
static mut OBSERVED_PC: usize = 0;

pub fn text_range() -> (usize, usize) {
    unsafe extern "C" {
        static text_start: u8;
        static text_end: u8;
    }
    (
        core::ptr::addr_of!(text_start) as usize,
        core::ptr::addr_of!(text_end) as usize,
    )
}

/// Only a single armed fault at an exact assembly site may resume S mode.
/// All other supervisor exceptions continue through the fatal kernel path.
pub unsafe fn recover(frame: &TrapFrame) -> Option<*const TrapFrame> {
    unsafe {
        if EXPECTED.resume == 0 {
            return None;
        }
        assert_eq!(
            frame.cause, EXPECTED.cause,
            "unexpected supervisor probe cause"
        );
        assert_eq!(frame.pc, EXPECTED.pc, "unexpected supervisor probe site");
        assert_eq!(
            frame.value, EXPECTED.address,
            "unexpected supervisor probe address"
        );
        assert_ne!(frame.status & 256, 0);
        SAVED = *frame;
        OBSERVED_PC = frame.pc;
        SAVED.pc = EXPECTED.resume;
        EXPECTED.resume = 0;
        EXPECTED.observed = true;
        Some(core::ptr::addr_of!(SAVED))
    }
}

unsafe fn probe(
    name: &str,
    cause: usize,
    site: usize,
    target: usize,
    resume: usize,
    run: unsafe extern "C" fn(),
) {
    unsafe {
        EXPECTED = Expected {
            cause,
            pc: site,
            address: target,
            resume,
            observed: false,
        };
        run();
        assert!(
            EXPECTED.observed && EXPECTED.resume == 0,
            "permission probe did not fault"
        );
        crate::log!(
            "KERNEL_PROBE name={} cause={} pc={:#x} stval={:#x} spp=1\n",
            name,
            SAVED.cause,
            OBSERVED_PC,
            SAVED.value
        );
    }
}

pub unsafe fn test(root: usize, permanent: usize) {
    unsafe extern "C" {
        static text_start: u8;
        static text_end: u8;
        static rodata_start: u8;
        static rodata_end: u8;
        static data_start: u8;
        static kernel_end: u8;
        static probe_text_target: u8;
        static probe_rodata_target: u8;
        static mut probe_data_target: u32;
        fn probe_write_text();
        fn probe_write_text_site();
        fn probe_write_text_resume();
        fn probe_write_rodata();
        fn probe_write_rodata_site();
        fn probe_write_rodata_resume();
        fn probe_execute_data();
        fn probe_execute_data_resume();
    }
    let text = core::ptr::addr_of!(text_start) as usize;
    let text_limit = core::ptr::addr_of!(text_end) as usize;
    let ro = core::ptr::addr_of!(rodata_start) as usize;
    let ro_end = core::ptr::addr_of!(rodata_end) as usize;
    let data = core::ptr::addr_of!(data_start) as usize;
    let end = core::ptr::addr_of!(kernel_end) as usize;
    let text_flags = memory::kernel_flags(root, text).unwrap();
    let ro_flags = memory::kernel_flags(root, ro).unwrap();
    let data_flags = memory::kernel_flags(root, data).unwrap();
    assert_eq!(text_flags, memory::R | memory::X);
    assert_eq!(ro_flags, memory::R);
    assert_eq!(data_flags, memory::R | memory::W);
    let audit = memory::audit(root, text, text_limit);
    assert_eq!(audit, (0, 0));
    crate::log!(
        "KERNEL_LAYOUT root={:#x} permanent_pages={} text_start={:#x} text_end={:#x} rodata_start={:#x} rodata_end={:#x} data_start={:#x} data_end={:#x} text_flags={} rodata_flags={} data_flags={} wx_leaves={} text_write_aliases={}\n",
        root,
        permanent,
        text,
        text_limit,
        ro,
        ro_end,
        data,
        end,
        text_flags,
        ro_flags,
        data_flags,
        audit.0,
        audit.1
    );
    // A real RW data access must succeed before exercising fault recovery.
    unsafe {
        let target = core::ptr::addr_of_mut!(probe_data_target);
        target.write_volatile(0x00008067);
        assert_eq!(target.read_volatile(), 0x00008067);
        core::arch::asm!("fence.i");
        probe(
            "write_text",
            15,
            probe_write_text_site as usize,
            core::ptr::addr_of!(probe_text_target) as usize,
            probe_write_text_resume as usize,
            probe_write_text,
        );
        probe(
            "write_rodata",
            15,
            probe_write_rodata_site as usize,
            core::ptr::addr_of!(probe_rodata_target) as usize,
            probe_write_rodata_resume as usize,
            probe_write_rodata,
        );
        probe(
            "execute_data",
            12,
            core::ptr::addr_of!(probe_data_target) as usize,
            core::ptr::addr_of!(probe_data_target) as usize,
            probe_execute_data_resume as usize,
            probe_execute_data,
        );
    }
    crate::log!("TEST kernel_permissions PASS rx_r_rw_nx_hardware\n");
}

use core::arch::asm;

pub fn sbi(eid: usize, fid: usize, a0: usize, a1: usize) -> (isize, usize) {
    let (error, value);
    unsafe {
        asm!("ecall", inlateout("a0") a0 => error, inlateout("a1") a1 => value,
            in("a6") fid, in("a7") eid, options(nostack));
    }
    (error, value)
}

pub fn putchar(byte: u8) {
    // Legacy SBI console returns only a0; a1 is nevertheless declared clobbered.
    unsafe {
        asm!("ecall", inlateout("a0") byte as usize => _, lateout("a1") _,
            in("a7") 1usize, options(nostack));
    }
}

pub fn time() -> u64 {
    let value;
    unsafe {
        asm!("rdtime {}", out(reg) value, options(nomem, nostack));
    }
    value
}

pub fn set_timer(deadline: u64) {
    assert_eq!(sbi(0x5449_4d45, 0, deadline as usize, 0).0, 0, "SBI TIME");
}

pub fn timer_enable(enabled: bool) {
    unsafe {
        if enabled {
            asm!("csrs sie, {}", in(reg) 1usize << 5);
        } else {
            asm!("csrc sie, {}", in(reg) 1usize << 5);
        }
    }
}

pub fn activate(root: usize) {
    unsafe {
        asm!("csrw satp, {}", "sfence.vma", in(reg) (8usize << 60) | (root >> 12));
    }
}

pub fn init_trap() {
    unsafe extern "C" {
        fn trap_entry();
    }
    unsafe {
        asm!("csrw stvec, {}", in(reg) trap_entry as usize);
    }
}

pub fn shutdown(failed: bool) -> ! {
    let result = sbi(0x5352_5354, 0, 0, usize::from(failed));
    crate::log!("FATAL SBI shutdown returned {:?}\n", result);
    loop {
        unsafe {
            asm!("wfi");
        }
    }
}

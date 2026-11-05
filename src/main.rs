#![no_std]
#![no_main]
#![allow(static_mut_refs)]

mod arch;
mod block;
mod block_tests;
mod console;
mod disk_boot;
mod elf;
mod elf_tests;
mod fdt;
mod memory;
mod permissions;
mod read_fd;
mod runtime;
mod transport_probe;

use core::arch::{asm, global_asm};
use memory::{AddressSpace, PAGE, R, USER_TOP};

global_asm!(include_str!("boot.S"));
global_asm!(include_str!("trap.S"));
global_asm!(include_str!("permission_probes.S"));

const WORKERS: &[u8] = include_bytes!(concat!(env!("ALVENX_USER_DIR"), "/workers.elf"));
const BAD_POINTER: &[u8] = include_bytes!(concat!(env!("ALVENX_USER_DIR"), "/bad_pointer.elf"));
const PROTECTION: &[u8] = include_bytes!(concat!(env!("ALVENX_USER_DIR"), "/protection_fault.elf"));
const WRITE_RX: &[u8] = include_bytes!(concat!(env!("ALVENX_USER_DIR"), "/write_rx.elf"));
const EXECUTE_STACK: &[u8] = include_bytes!(concat!(env!("ALVENX_USER_DIR"), "/execute_stack.elf"));
const BENCH: &[u8] = include_bytes!(concat!(env!("ALVENX_USER_DIR"), "/yield_bench.elf"));

#[derive(Clone, Copy)]
#[repr(C)]
pub struct TrapFrame {
    x: [usize; 32],
    pc: usize,
    status: usize,
    cause: usize,
    value: usize,
}
impl TrapFrame {
    const fn empty() -> Self {
        Self {
            x: [0; 32],
            pc: 0,
            status: 0,
            cause: 0,
            value: 0,
        }
    }
}
const _: () = {
    assert!(core::mem::size_of::<TrapFrame>() == 288);
    assert!(core::mem::offset_of!(TrapFrame, pc) == 256);
    assert!(core::mem::offset_of!(TrapFrame, status) == 264);
};

struct Task {
    frame: TrapFrame,
    space: AddressSpace,
    state: u8, // 0 empty, 1 runnable, 2 exited, 3 faulted
    exit: i32,
    runs: usize,
    timer_traps: usize,
    writes: usize,
    bytes: usize,
    efault: usize,
    enosys: usize,
    yields: usize,
    fault_cause: usize,
    fault_va: usize,
    fd: read_fd::State,
}
impl Task {
    const fn empty() -> Self {
        Self {
            frame: TrapFrame::empty(),
            space: AddressSpace::empty(),
            state: 0,
            exit: 0,
            runs: 0,
            timer_traps: 0,
            writes: 0,
            bytes: 0,
            efault: 0,
            enosys: 0,
            yields: 0,
            fault_cause: 0,
            fault_va: 0,
            fd: read_fd::State::empty(),
        }
    }
}

static mut TASKS: [Task; 6] = [const { Task::empty() }; 6];
static mut CURRENT: usize = 0;
static mut TASK_COUNT: usize = 0;
static mut KERNEL_ROOT: usize = 0;
static mut PERMANENT_PAGES: usize = 0;
static mut TIMEBASE: u64 = 0;
static mut PHASE: usize = 0;
static mut PHASE_START: u64 = 0;
static mut YIELD_SWITCHES: usize = 0;
static mut TIMER_SWITCHES: usize = 0;
static mut TIMER_TRAPS: usize = 0;
static mut FIRST_EXIT_CHECKED: bool = false;

#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    log!("KERNEL FAIL {}\n", info);
    arch::shutdown(true)
}

#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(hart: usize, dtb: usize) -> ! {
    log!("ALVENX native version=0.6.0 hart={} dtb={:#x}\n", hart, dtb);
    assert_eq!(hart, 0);
    assert!(
        arch::sbi(0x10, 3, 0x5449_4d45, 0).1 != 0,
        "SBI TIME unavailable"
    );
    assert!(
        arch::sbi(0x10, 3, 0x5352_5354, 0).1 != 0,
        "SBI SRST unavailable"
    );
    unsafe extern "C" {
        static kernel_end: u8;
    }
    let end = core::ptr::addr_of!(kernel_end) as usize;
    unsafe {
        TIMEBASE = fdt::timebase(dtb).expect("FDT timebase-frequency");
        log!(
            "PLATFORM timebase_hz={} ram_end=0x88000000 reserved_fdt_start={:#x}\n",
            TIMEBASE,
            dtb
        );
        memory::init(end, dtb.min(0x8800_0000));
        assert_eq!(dtb, 0x87e0_0000, "stage03a fixed virt FDT mapping");
        memory::self_test();
        KERNEL_ROOT = memory::init_kernel();
        PERMANENT_PAGES = memory::stats().1;
        assert_eq!(PERMANENT_PAGES, memory::KERNEL_TABLE_PAGES);
        arch::activate(KERNEL_ROOT);
        arch::init_trap();
        permissions::test(KERNEL_ROOT, PERMANENT_PAGES);
        for slot in 0..memory::VIRTIO_SLOTS {
            assert_eq!(
                memory::kernel_flags(KERNEL_ROOT, memory::VIRTIO_VA + slot * PAGE),
                Some(memory::R | memory::W)
            );
        }
        log!(
            "MMIO_LAYOUT virtual_start={:#x} physical_start={:#x} pages={} flags=6 permanent_pages={}\n",
            memory::VIRTIO_VA,
            memory::VIRTIO_PA,
            memory::VIRTIO_SLOTS,
            PERMANENT_PAGES
        );
        elf_negative_tests();
        elf_tests::rollback(WORKERS, TIMEBASE);
        if let Some(loaded) = disk_boot::load(TIMEBASE) {
            let extent = match read_fd::Extent::parse(
                &loaded.extent_header,
                loaded.capacity,
                loaded.payload_offset,
                loaded.bytes,
            ) {
                Ok(extent) => extent,
                Err(error) => {
                    let mut space = loaded.space;
                    let before = memory::stats().1;
                    space.destroy();
                    log!(
                        "FD_REJECT error={} user_freed={} remaining_pages={}\n",
                        error,
                        before - memory::stats().1,
                        memory::stats().1
                    );
                    after_disk()
                }
            };
            PHASE = if extent.is_some() { 4 } else { 3 };
            TASK_COUNT = 1;
            CURRENT = 0;
            arch::timer_enable(false);
            arch::set_timer(u64::MAX);
            add_loaded_task(0, loaded.space, loaded.entry, 0, loaded.bytes);
            if let Some(extent) = extent {
                TASKS[0].fd.open(extent, TIMEBASE);
                log!("FD_EXEC_BEGIN phase=4 pid=1 input_valid=0\n");
            } else {
                log!("DISK_EXEC_BEGIN phase=3 pid=1 input_valid=0\n");
            }
            PHASE_START = arch::time();
            dispatch(0)
        }
        after_disk()
    }
}

unsafe fn elf_negative_tests() {
    let before = memory::stats().1;
    let mut damaged = [0u8; WORKERS.len()];
    damaged.copy_from_slice(WORKERS);
    damaged[0] = 0;
    assert!(unsafe { elf::load(&damaged) }.is_err());
    damaged.copy_from_slice(WORKERS);
    let phoff = u64::from_le_bytes(damaged[32..40].try_into().unwrap()) as usize;
    let count = u16::from_le_bytes(damaged[56..58].try_into().unwrap()) as usize;
    let load_header = (0..count)
        .map(|i| phoff + i * 56)
        .find(|at| u32::from_le_bytes(damaged[*at..*at + 4].try_into().unwrap()) == 1)
        .expect("fixture PT_LOAD");
    damaged[load_header + 32..load_header + 40].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(unsafe { elf::load(&damaged) }.is_err());
    damaged.copy_from_slice(WORKERS);
    damaged[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(unsafe { elf::load(&damaged) }.is_err());
    assert_eq!(before, memory::stats().1);
    log!("TEST elf_reject PASS magic_file_range_header_overflow_no_frame_leak\n");
}

unsafe fn add_task(index: usize, image: &[u8], argument: usize) {
    let (space, pc) = unsafe { elf::load(image).expect("load user ELF") };
    unsafe {
        add_loaded_task(index, space, pc, argument, image.len());
    }
}

unsafe fn add_loaded_task(
    index: usize,
    space: AddressSpace,
    pc: usize,
    argument: usize,
    image_bytes: usize,
) {
    let mut status: usize;
    unsafe {
        asm!("csrr {}, sstatus", out(reg) status);
    }
    let mut frame = TrapFrame::empty();
    frame.pc = pc;
    frame.status = (status & !((1 << 8) | (1 << 1))) | (1 << 5);
    frame.x[2] = USER_TOP;
    frame.x[10] = argument;
    let mut task = Task::empty();
    task.frame = frame;
    task.space = space;
    task.state = 1;
    log!(
        "LOAD phase={} pid={} elf_bytes={} root={:#x} pc={:#x} stack={:#x}\n",
        unsafe { PHASE },
        index + 1,
        image_bytes,
        task.space.root,
        pc,
        USER_TOP
    );
    let (text_start, text_end) = permissions::text_range();
    let audit = memory::audit(task.space.root, text_start, text_end);
    let text_flags = task.space.flags(0x10000).unwrap();
    let stack_flags = task.space.flags(USER_TOP - PAGE).unwrap();
    let guard_mapped = usize::from(task.space.flags(USER_TOP - 3 * PAGE).is_some());
    assert_eq!(text_flags, memory::R | memory::X | memory::U);
    assert_eq!(stack_flags, memory::R | memory::W | memory::U);
    assert_eq!(guard_mapped, 0);
    assert_eq!(audit, (0, 0));
    log!(
        "USER_ACCESS phase={} pid={} text_va=0x10000 text_flags={} stack_va={:#x} stack_flags={} guard_va={:#x} guard_mapped={} wx_leaves={} kernel_text_write_aliases={}\n",
        unsafe { PHASE },
        index + 1,
        text_flags,
        USER_TOP - PAGE,
        stack_flags,
        USER_TOP - 3 * PAGE,
        guard_mapped,
        audit.0,
        audit.1
    );
    unsafe {
        assert!(
            TASKS[index].fd.is_closed(),
            "task replacement cannot lose a device owner"
        );
        TASKS[index] = task;
    }
}

unsafe fn prepare_phase(phase: usize) {
    unsafe {
        PHASE = phase;
        CURRENT = 0;
        YIELD_SWITCHES = 0;
        TIMER_SWITCHES = 0;
        TIMER_TRAPS = 0;
        FIRST_EXIT_CHECKED = false;
        if phase == 0 {
            TASK_COUNT = 6;
            add_task(0, WORKERS, 1);
            add_task(1, WORKERS, 2);
            add_task(2, BAD_POINTER, 0);
            add_task(3, PROTECTION, 0);
            add_task(4, WRITE_RX, 0);
            add_task(5, EXECUTE_STACK, 0);
            let pa = TASKS[0].space.translate(0x20000, R).unwrap();
            let pb = TASKS[1].space.translate(0x20000, R).unwrap();
            assert_ne!(pa, pb);
            log!(
                "ISOLATION shared_va=0x20000 pa_a={:#x} pa_b={:#x}\n",
                pa,
                pb
            );
            arch::set_timer(arch::time() + TIMEBASE / 1000);
            arch::timer_enable(true);
        } else {
            TASK_COUNT = 2;
            arch::timer_enable(false);
            arch::set_timer(u64::MAX);
            let iterations = if phase == 1 { 1000 } else { 10000 };
            add_task(0, BENCH, iterations);
            add_task(1, BENCH, iterations);
            log!(
                "BENCH_BEGIN phase={} iterations_per_task={} timer=off\n",
                phase,
                iterations
            );
        }
        PHASE_START = arch::time();
    }
}

unsafe fn select_next() -> usize {
    unsafe {
        for offset in 1..=TASK_COUNT {
            let index = (CURRENT + offset) % TASK_COUNT;
            if TASKS[index].state == 1 {
                return index;
            }
        }
        finish_phase()
    }
}

unsafe fn frame_for(index: usize) -> *const TrapFrame {
    unsafe {
        CURRENT = index;
        TASKS[index].runs += 1;
        arch::activate(TASKS[index].space.root);
        core::ptr::addr_of!(TASKS[index].frame)
    }
}

unsafe fn dispatch(index: usize) -> ! {
    unsafe extern "C" {
        fn enter_user(frame: *const TrapFrame) -> !;
    }
    unsafe { enter_user(frame_for(index)) }
}

fn user_write(task: &mut Task, fd: usize, pointer: usize, length: usize) -> isize {
    if fd != 1 && fd != 2 {
        return -9;
    }
    if length > 1024 {
        return -22;
    }
    if pointer.checked_add(length).is_none() {
        task.efault += 1;
        return -14;
    }
    // All-or-nothing validation, including a buffer spanning two pages.
    if !(0..length).all(|i| task.space.translate(pointer + i, R).is_some()) {
        task.efault += 1;
        return -14;
    }
    let disk = unsafe { PHASE == 3 || PHASE == 4 };
    if disk {
        if unsafe { PHASE == 4 } {
            log!(
                "FD_WRITE seq={} pid=1 fd={} requested={} returned={} hex=",
                task.writes + 1,
                fd,
                length,
                length
            );
        } else {
            log!(
                "DISK_WRITE pid=1 fd={} requested={} returned={} hex=",
                fd,
                length,
                length
            );
        }
    }
    for i in 0..length {
        let pa = task.space.translate(pointer + i, R).unwrap();
        let byte = unsafe { (pa as *const u8).read_volatile() };
        if disk {
            log!("{:02x}", byte);
        } else {
            arch::putchar(byte);
        }
    }
    if disk {
        log!("\n");
    }
    task.writes += 1;
    task.bytes += length;
    length as isize
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn rust_trap(incoming: &TrapFrame) -> *const TrapFrame {
    if incoming.status & (1 << 8) != 0 {
        if let Some(frame) = unsafe { permissions::recover(incoming) } {
            return frame;
        }
        panic!(
            "supervisor trap cause={:#x} pc={:#x} stval={:#x}",
            incoming.cause, incoming.pc, incoming.value
        );
    }
    unsafe {
        let old = CURRENT;
        TASKS[old].frame = *incoming;
        let mut next = old;
        match incoming.cause {
            8 => {
                let task = &mut TASKS[old];
                task.frame.pc += 4;
                let nr = task.frame.x[17];
                let args = [task.frame.x[10], task.frame.x[11], task.frame.x[12]];
                let result = match nr {
                    62 => task.fd.seek(args[0], args[1] as i64, args[2]),
                    63 => {
                        let value = task.fd.read(&task.space, args[0], args[1], args[2]);
                        if value == -14 {
                            task.efault += 1;
                        }
                        value
                    }
                    57 => task.fd.close(args[0], "explicit"),
                    64 => user_write(task, args[0], args[1], args[2]),
                    172 => (old + 1) as isize,
                    124 => {
                        task.yields += 1;
                        next = select_next();
                        if next != old {
                            YIELD_SWITCHES += 1;
                        }
                        0
                    }
                    93 => {
                        task.fd.cleanup();
                        task.exit = args[0] as i32;
                        task.state = 2;
                        if PHASE == 0 && old < 2 && !FIRST_EXIT_CHECKED {
                            assert!(
                                TASKS[0].runs > 0 && TASKS[1].runs > 0 && TIMER_SWITCHES > 0,
                                "workers must run before first worker exit"
                            );
                            FIRST_EXIT_CHECKED = true;
                        }
                        next = select_next();
                        0
                    }
                    _ => {
                        task.enosys += 1;
                        -38
                    }
                };
                TASKS[old].frame.x[10] = result as usize;
            }
            cause if cause == (1usize << 63) | 5 => {
                assert_eq!(PHASE, 0, "timer must be off in benchmark");
                TIMER_TRAPS += 1;
                TASKS[old].timer_traps += 1;
                arch::set_timer(arch::time() + TIMEBASE / 1000);
                next = select_next();
                if next != old {
                    TIMER_SWITCHES += 1;
                }
            }
            cause => {
                TASKS[old].fd.cleanup();
                TASKS[old].state = 3;
                TASKS[old].fault_cause = cause;
                TASKS[old].fault_va = incoming.value;
                log!(
                    "USER_FAULT pid={} cause={} pc={:#x} stval={:#x}\n",
                    old + 1,
                    cause,
                    incoming.pc,
                    incoming.value
                );
                next = select_next();
            }
        }
        frame_for(next)
    }
}

unsafe fn finish_phase() -> ! {
    let elapsed = arch::time() - unsafe { PHASE_START };
    unsafe {
        arch::timer_enable(false);
        arch::set_timer(u64::MAX);
        for (index, task) in TASKS[..TASK_COUNT].iter().enumerate() {
            log!(
                "TASK phase={} pid={} state={} exit={} runs={} timers={} yields={} writes={} bytes={} efault={} enosys={} fault={}\n",
                PHASE,
                index + 1,
                task.state,
                task.exit,
                task.runs,
                task.timer_traps,
                task.yields,
                task.writes,
                task.bytes,
                task.efault,
                task.enosys,
                task.fault_cause
            );
        }
        if PHASE == 0 {
            for (index, expected) in [(0, 37), (1, 41), (2, 43)] {
                assert_eq!(TASKS[index].state, 2);
                assert_eq!(TASKS[index].exit, expected);
            }
            assert!(TASKS[0].timer_traps > 0 && TASKS[1].timer_traps > 0);
            for index in 0..2 {
                let task = &TASKS[index];
                assert_eq!(task.enosys, 1);
                assert_eq!(task.writes, 1);
                let pa = task.space.translate(0x20000, R).unwrap();
                assert_eq!((pa as *const usize).read_volatile(), index + 1);
            }
            assert_eq!(TASKS[2].efault, 2);
            assert_eq!(TASKS[2].writes, 0);
            for (index, cause, address) in [
                (3, 13, 0x8020_0000),
                (4, 15, 0x10000),
                (5, 12, USER_TOP - 16),
            ] {
                assert_eq!(TASKS[index].state, 3);
                assert_eq!(TASKS[index].fault_cause, cause);
                assert_eq!(TASKS[index].fault_va, address);
                assert_eq!(
                    TASKS[index].yields + TASKS[index].writes + TASKS[index].enosys,
                    0
                );
            }
            log!(
                "TEST user_syscalls_registers_isolation_timer PASS timer_traps={} timer_switches={}\n",
                TIMER_TRAPS,
                TIMER_SWITCHES
            );
        } else if PHASE == 4 {
            let task = &TASKS[0];
            assert_eq!(task.state, 2, "controlled fd program exits normally");
            assert!(task.fd.is_closed() && task.fd.reads > 0 && task.writes > 0);
            assert_eq!(
                task.timer_traps + task.yields + task.enosys + task.fault_cause,
                0
            );
        } else if PHASE == 3 {
            let task = &TASKS[0];
            assert_eq!(task.state, 2, "disk user must exit normally");
            assert_eq!(task.writes, 1);
            assert!(task.bytes > 0);
            assert_eq!(task.runs, 2);
            assert_eq!(
                task.timer_traps + task.yields + task.efault + task.enosys + task.fault_cause,
                0
            );
        } else {
            let iterations = if PHASE == 1 { 1000 } else { 10000 };
            for index in 0..2 {
                assert_eq!(TASKS[index].state, 2);
                assert_eq!(TASKS[index].exit, 51 + index as i32);
                assert_eq!(TASKS[index].yields, iterations);
            }
            assert_eq!(YIELD_SWITCHES, iterations * 2);
            assert_eq!(TIMER_TRAPS, 0);
            log!(
                "METRIC yield phase={} iterations_per_task={} yield_calls={} switches={} guest_time_ticks={} timebase_hz={} guest_virtual_ns={}\n",
                PHASE,
                iterations,
                iterations * 2,
                YIELD_SWITCHES,
                elapsed,
                TIMEBASE,
                elapsed * 1_000_000_000 / TIMEBASE
            );
        }
        // Switch away before returning the currently active page tables to the pool.
        arch::activate(KERNEL_ROOT);
        for task in &mut TASKS[..TASK_COUNT] {
            task.space.destroy();
            *task = Task::empty();
        }
        let (total, used, high) = memory::stats();
        assert_eq!(
            used, PERMANENT_PAGES,
            "all user pages and tables must be reclaimed"
        );
        log!(
            "MEMORY phase={} total_pages={} allocated_pages={} free_pages={} high_water_pages={} page_bytes={}\n",
            PHASE,
            total,
            used,
            total - used,
            high,
            PAGE
        );
        if PHASE == 4 {
            log!("FD_EXEC_END phase=4 remaining_pages={}\n", used);
            after_disk()
        }
        if PHASE == 3 {
            log!("DISK_EXEC_END phase=3 remaining_pages={}\n", used);
            after_disk()
        }
        if PHASE < 2 {
            prepare_phase(PHASE + 1);
            dispatch(0)
        }
        log!("RESULT functional=PASS benchmark_cases=2 official_score=UNMEASURED\n");
        arch::shutdown(false)
    }
}

unsafe fn after_disk() -> ! {
    unsafe {
        assert_eq!(memory::stats().1, PERMANENT_PAGES);
        block_tests::run(TIMEBASE);
        prepare_phase(0);
        dispatch(0)
    }
}

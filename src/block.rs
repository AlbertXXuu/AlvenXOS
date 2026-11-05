//! Minimal read-only modern VirtIO MMIO, split queue, one in-flight request.
//! This implementation follows the Virtio 1.2 interface; no driver source is imported.
use crate::{arch, memory};
use core::arch::asm;
use core::sync::atomic::{AtomicBool, Ordering};

static OWNED: AtomicBool = AtomicBool::new(false);
struct Ownership {
    release_on_drop: bool,
}
impl Ownership {
    fn take() -> Result<Self, Error> {
        OWNED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self {
                release_on_drop: true,
            })
            .map_err(|_| Error::Busy)
    }
    fn release(&mut self) {
        OWNED.store(false, Ordering::Release);
        self.release_on_drop = false;
    }
}
impl Drop for Ownership {
    fn drop(&mut self) {
        if self.release_on_drop {
            OWNED.store(false, Ordering::Release);
        }
    }
}

pub const MAX_READ: usize = 2048;
pub const QUEUE_SIZE: usize = 8;
pub const POLL_LIMIT: usize = 1_000_000;
const AVAIL: usize = 0x100;
const USED: usize = 0x200;
const HEADER: usize = 0x400;
const STATUS_BYTE: usize = HEADER + 16;
const ACCEPTED: u64 = (1 << 32) | (1 << 5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Busy,
    Absent,
    Multiple,
    Transport,
    Features,
    Capacity,
    Queue,
    Frames,
    Range,
    Overflow,
    TooLong,
    Io,
    Timeout,
    Poisoned,
    Protocol,
    ResetTimeout,
}
impl Error {
    pub fn token(self) -> &'static str {
        match self {
            Self::Busy => "busy",
            Self::Absent => "absent",
            Self::Multiple => "multiple",
            Self::Transport => "transport",
            Self::Features => "features",
            Self::Capacity => "capacity",
            Self::Queue => "queue",
            Self::Frames => "frames",
            Self::Range => "range",
            Self::Overflow => "overflow",
            Self::TooLong => "too_long",
            Self::Io => "ioerr",
            Self::Timeout => "timeout",
            Self::Poisoned => "poisoned",
            Self::Protocol => "protocol",
            Self::ResetTimeout => "reset_timeout",
        }
    }
}
#[derive(Clone, Copy, Default)]
pub struct Counters {
    pub submitted: usize,
    pub completed: usize,
    pub notified: usize,
}
#[derive(Clone, Copy, Default)]
pub struct Wait {
    pub polls: usize,
    pub ticks: u64,
}

fn fence() {
    unsafe {
        asm!("fence iorw, iorw");
    }
}
fn read32(address: usize) -> u32 {
    unsafe { (address as *const u32).read_volatile() }
}
fn write32(address: usize, value: u32) {
    unsafe {
        (address as *mut u32).write_volatile(value);
    }
}
fn read16(address: usize) -> u16 {
    unsafe { (address as *const u16).read_volatile() }
}
fn write16(address: usize, value: u16) {
    unsafe {
        (address as *mut u16).write_volatile(value);
    }
}
fn write64(address: usize, value: u64) {
    unsafe {
        (address as *mut u64).write_volatile(value);
    }
}

fn reset(base: usize, budget: u64, hide_ack: bool, observed: &mut Wait) -> Result<(), Error> {
    write32(base + 0x70, 0);
    fence();
    let start = arch::time();
    for polls in 1..=POLL_LIMIT {
        let status = read32(base + 0x70);
        *observed = Wait {
            polls,
            ticks: arch::time() - start,
        };
        if !hide_ack && status == 0 {
            // Status=0 acknowledges reset. Only now has the device relinquished DMA.
            fence();
            return Ok(());
        }
        if observed.ticks >= budget {
            break;
        }
    }
    Err(Error::ResetTimeout)
}

pub struct BlockDevice {
    owner: Ownership,
    base: usize,
    physical: usize,
    capacity: u64,
    ring: usize,
    bounce: usize,
    budget_ticks: u64,
    avail: u16,
    used: u16,
    counts: Counters,
    pub last_wait: Wait,
    pub last_reset_wait: Wait,
    pub last_status: u8,
    pub last_used_len: u32,
    poisoned: bool,
    quarantined: bool,
}
impl BlockDevice {
    pub fn open(timebase: u64) -> Result<Self, Error> {
        let owner = Ownership::take()?;
        let budget = timebase.div_ceil(20).max(1);
        let mut found = None;
        for slot in 0..memory::VIRTIO_SLOTS {
            let base = memory::VIRTIO_VA + slot * memory::PAGE;
            if !crate::transport_probe::is_modern_block(|offset| read32(base + offset)) {
                continue;
            }
            if found.is_some() {
                return Err(Error::Multiple);
            }
            found = Some((base, memory::VIRTIO_PA + slot * memory::PAGE));
        }
        let (base, physical) = found.ok_or(Error::Absent)?;
        reset(base, budget, false, &mut Wait::default())?;
        write32(base + 0x70, 1);
        write32(base + 0x70, 3);
        write32(base + 0x14, 0);
        let low = read32(base + 0x10);
        write32(base + 0x14, 1);
        let high = read32(base + 0x10);
        if low & (1 << 5) == 0 || high & 1 == 0 {
            return Err(Error::Features);
        }
        write32(base + 0x24, 0);
        write32(base + 0x20, ACCEPTED as u32);
        write32(base + 0x24, 1);
        write32(base + 0x20, (ACCEPTED >> 32) as u32);
        write32(base + 0x70, 11);
        if read32(base + 0x70) != 11 {
            return Err(Error::Features);
        }
        let mut capacity = None;
        for _ in 0..64 {
            let generation = read32(base + 0xfc);
            let sectors = read32(base + 0x100) as u64 | ((read32(base + 0x104) as u64) << 32);
            fence();
            if generation == read32(base + 0xfc) {
                capacity = sectors.checked_mul(512).filter(|n| *n > 0);
                break;
            }
        }
        let capacity = capacity.ok_or(Error::Capacity)?;
        write32(base + 0x30, 0);
        if read32(base + 0x34) < QUEUE_SIZE as u32 || read32(base + 0x44) != 0 {
            return Err(Error::Queue);
        }
        let ring = unsafe { memory::alloc().map_err(|_| Error::Frames)? };
        let bounce = match unsafe { memory::alloc() } {
            Ok(page) => page,
            Err(_) => {
                unsafe {
                    memory::free(ring).unwrap();
                }
                return Err(Error::Frames);
            }
        };
        // ring: descriptors [0,128), avail @0x100, used @0x200,
        // request header/status @0x400. No region overlaps; all required alignments hold.
        write16(ring + AVAIL, 1); // polling driver requests no interrupts
        write32(base + 0x38, QUEUE_SIZE as u32);
        for (register, address) in [(0x80, ring), (0x90, ring + AVAIL), (0xa0, ring + USED)] {
            write32(base + register, address as u32);
            write32(base + register + 4, (address >> 32) as u32);
        }
        fence();
        write32(base + 0x44, 1);
        write32(base + 0x70, 15);
        let mut device = Self {
            owner,
            base,
            physical,
            capacity,
            ring,
            bounce,
            budget_ticks: budget,
            avail: 0,
            used: 0,
            counts: Counters::default(),
            last_wait: Wait::default(),
            last_reset_wait: Wait::default(),
            last_status: 255,
            last_used_len: 0,
            poisoned: false,
            quarantined: false,
        };
        if read32(base + 0x70) != 15 {
            device.close()?;
            return Err(Error::Transport);
        }
        Ok(device)
    }
    pub fn counters(&self) -> Counters {
        self.counts
    }
    pub fn physical(&self) -> usize {
        self.physical
    }
    pub fn capacity(&self) -> u64 {
        self.capacity
    }
    pub fn ring(&self) -> usize {
        self.ring
    }
    pub fn bounce(&self) -> usize {
        self.bounce
    }
    pub fn budget_ticks(&self) -> u64 {
        self.budget_ticks
    }
    pub fn negotiated_features(&self) -> u64 {
        ACCEPTED
    }

    fn descriptor(&self, index: usize, address: usize, length: u32, flags: u16, next: u16) {
        let at = self.ring + index * 16;
        write64(at, address as u64);
        write32(at + 8, length);
        write16(at + 12, flags);
        write16(at + 14, next);
    }

    pub fn read_at(&mut self, offset: u64, out: &mut [u8]) -> Result<(), Error> {
        self.read_impl(offset, out, false)
    }
    /// Development-only injection: notify normally, but deliberately ignore completion.
    /// This tests bounded waiting/reset; it does not represent a naturally hung device.
    pub fn injected_timeout(&mut self, offset: u64, out: &mut [u8]) -> Result<(), Error> {
        self.read_impl(offset, out, true)
    }
    fn read_impl(&mut self, offset: u64, out: &mut [u8], hide_used: bool) -> Result<(), Error> {
        if self.poisoned || self.quarantined || self.ring == 0 {
            return Err(Error::Poisoned);
        }
        let end = offset
            .checked_add(out.len() as u64)
            .ok_or(Error::Overflow)?;
        if offset > self.capacity || end > self.capacity {
            return Err(Error::Range);
        }
        if out.len() > MAX_READ {
            return Err(Error::TooLong);
        }
        if out.is_empty() {
            return Ok(());
        }
        let within = (offset % 512) as usize;
        let bytes = (within + out.len() + 511) & !511;
        assert!(bytes <= memory::PAGE);
        write32(self.ring + HEADER, 0); // VIRTIO_BLK_T_IN only
        write32(self.ring + HEADER + 4, 0);
        write64(self.ring + HEADER + 8, offset / 512);
        unsafe {
            ((self.ring + STATUS_BYTE) as *mut u8).write_volatile(255);
        }
        self.descriptor(0, self.ring + HEADER, 16, 1, 1);
        self.descriptor(1, self.bounce, bytes as u32, 3, 2);
        self.descriptor(2, self.ring + STATUS_BYTE, 1, 2, 0);
        write16(
            self.ring + AVAIL + 4 + (self.avail as usize % QUEUE_SIZE) * 2,
            0,
        );
        fence();
        self.avail = self.avail.wrapping_add(1);
        write16(self.ring + AVAIL + 2, self.avail);
        fence();
        self.counts.submitted += 1;
        write32(self.base + 0x50, 0);
        self.counts.notified += 1;
        let start = arch::time();
        for polls in 1..=POLL_LIMIT {
            let observed = read16(self.ring + USED + 2);
            self.last_wait = Wait {
                polls,
                ticks: arch::time() - start,
            };
            if !hide_used && observed != self.used {
                fence();
                if observed != self.used.wrapping_add(1) {
                    self.poisoned = true;
                    return Err(Error::Protocol);
                }
                let entry = self.ring + USED + 4 + (self.used as usize % QUEUE_SIZE) * 8;
                let id = read32(entry);
                self.last_used_len = read32(entry + 4);
                self.last_status =
                    unsafe { ((self.ring + STATUS_BYTE) as *const u8).read_volatile() };
                self.used = observed;
                self.counts.completed += 1;
                let irq = read32(self.base + 0x60) & 3;
                if irq != 0 {
                    write32(self.base + 0x64, irq);
                }
                if id != 0 || self.last_used_len < 1 || self.last_used_len > bytes as u32 + 1 {
                    self.poisoned = true;
                    return Err(Error::Protocol);
                }
                if self.last_status == 1 {
                    return Err(Error::Io);
                }
                if self.last_status != 0 || self.last_used_len != bytes as u32 + 1 {
                    self.poisoned = true;
                    return Err(Error::Protocol);
                }
                for (index, byte) in out.iter_mut().enumerate() {
                    *byte =
                        unsafe { ((self.bounce + within + index) as *const u8).read_volatile() };
                }
                return Ok(());
            }
            if self.last_wait.ticks >= self.budget_ticks {
                break;
            }
        }
        self.poisoned = true;
        Err(Error::Timeout)
    }

    pub fn close(&mut self) -> Result<Wait, Error> {
        self.close_impl(false)
    }
    /// Development-only: reset normally, but hide acknowledgement to exercise quarantine.
    pub fn injected_reset_timeout(&mut self) -> Result<Wait, Error> {
        self.close_impl(true)
    }
    fn close_impl(&mut self, hide_ack: bool) -> Result<Wait, Error> {
        if self.ring == 0 {
            return Ok(Wait::default());
        }
        // Closing revokes the right to submit even if reset later times out.
        self.poisoned = true;
        match reset(
            self.base,
            self.budget_ticks,
            hide_ack,
            &mut self.last_reset_wait,
        ) {
            Ok(()) => (),
            Err(error) => {
                self.quarantined = true;
                // Keep the exclusive lease even if this object is dropped.
                self.owner.release_on_drop = false;
                if !hide_ack {
                    crate::log!("BLOCK_QUARANTINE pages=2 reason=reset_timeout\n");
                }
                return Err(error);
            }
        }
        unsafe {
            memory::free(self.bounce).unwrap();
            memory::free(self.ring).unwrap();
        }
        self.ring = 0;
        self.bounce = 0;
        self.quarantined = false;
        self.poisoned = true;
        self.owner.release();
        Ok(self.last_reset_wait)
    }
}
impl Drop for BlockDevice {
    fn drop(&mut self) {
        // Never release memory until reset was observed. Failed reset quarantines it.
        if self.ring != 0 && !self.quarantined {
            let _ = self.close();
        }
    }
}

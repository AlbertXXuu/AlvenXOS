//! One task-owned, preopened read-only extent. No path lookup or shared file table.
use crate::{
    block::{BlockDevice, Counters, Error, Wait},
    memory::{self, AddressSpace, R, W},
};
use core::sync::atomic::{AtomicBool, Ordering};
pub const MAX: usize = 1024;
static ENTERED: AtomicBool = AtomicBool::new(false);
struct Gate;
impl Gate {
    fn enter() -> Self {
        let status: usize;
        unsafe {
            core::arch::asm!("csrr {}, sstatus", out(reg) status);
        }
        assert_eq!(status & 2, 0, "synchronous fd handler requires SIE=0");
        assert!(
            !ENTERED.swap(true, Ordering::Acquire),
            "fd handler reentered"
        );
        Self
    }
}
impl Drop for Gate {
    fn drop(&mut self) {
        ENTERED.store(false, Ordering::Release);
    }
}

#[derive(Clone, Copy)]
pub struct Extent {
    pub offset: u64,
    pub length: u64,
}
impl Extent {
    pub fn parse(
        raw: &[u8; 32],
        capacity: u64,
        elf_offset: u64,
        elf_length: usize,
    ) -> Result<Option<Self>, &'static str> {
        if raw.iter().all(|b| *b == 0) {
            return Ok(None);
        }
        if &raw[..8] != b"ALVXDATA" {
            return Err("magic");
        }
        if u32::from_le_bytes(raw[8..12].try_into().unwrap()) != 1 {
            return Err("version");
        }
        if u32::from_le_bytes(raw[12..16].try_into().unwrap()) != 32 {
            return Err("header_size");
        }
        let offset = u64::from_le_bytes(raw[16..24].try_into().unwrap());
        let length = u64::from_le_bytes(raw[24..32].try_into().unwrap());
        if length == 0 || length > 8192 {
            return Err("length");
        }
        let end = offset.checked_add(length).ok_or("overflow")?;
        if offset < 512 || end > capacity {
            return Err("range");
        }
        if offset < elf_offset + elf_length as u64 && elf_offset < end {
            return Err("overlap");
        }
        Ok(Some(Self { offset, length }))
    }
}

#[derive(PartialEq, Eq)]
struct Snapshot {
    data: [u8; MAX],
    length: usize,
}
impl Snapshot {
    fn take(space: &AddressSpace, pointer: usize, length: usize) -> Self {
        let mut result = Self {
            data: [0; MAX],
            length: 0,
        };
        if length > MAX || pointer.checked_add(length).is_none() {
            return result;
        }
        for i in 0..length {
            let Some(pa) = space.translate(pointer + i, R) else {
                break;
            };
            result.data[i] = unsafe { (pa as *const u8).read_volatile() };
            result.length += 1;
        }
        result
    }
}
impl core::fmt::Display for Snapshot {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.length == 0 {
            return out.write_str("-");
        }
        for b in &self.data[..self.length] {
            write!(out, "{:02x}", b)?;
        }
        Ok(())
    }
}

pub struct State {
    device: Option<BlockDevice>,
    extent: Extent,
    cursor: u64,
    pub reads: usize,
    closes: usize,
    configured: bool,
}
impl State {
    pub const fn empty() -> Self {
        Self {
            device: None,
            extent: Extent {
                offset: 0,
                length: 0,
            },
            cursor: 0,
            reads: 0,
            closes: 0,
            configured: false,
        }
    }
    pub fn open(&mut self, extent: Extent, timebase: u64) {
        assert!(!self.configured && self.device.is_none());
        let device = BlockDevice::open(timebase).expect("preopened fd exclusive device");
        assert!(extent.offset + extent.length <= device.capacity());
        crate::log!(
            "FD_OPEN phase=4 pid=1 fd=3 offset={} length={} cursor=0 ring={:#x} bounce={:#x} live_pages={} submitted=0 max_read={} sie=0\n",
            extent.offset,
            extent.length,
            device.ring(),
            device.bounce(),
            memory::stats().1,
            MAX
        );
        self.device = Some(device);
        self.extent = extent;
        self.configured = true;
    }
    pub fn read(
        &mut self,
        space: &AddressSpace,
        fd: usize,
        pointer: usize,
        length: usize,
    ) -> isize {
        let _gate = Gate::enter();
        self.reads += 1;
        let before = Snapshot::take(space, pointer, length);
        let position = self.cursor;
        let mut counts = Counters::default();
        let mut status = 255;
        let mut used = 0;
        let mut wait = Wait::default();
        let returned = if fd != 3 || self.device.is_none() {
            -9
        } else if length > MAX {
            -22
        } else if length == 0 {
            0
        } else if pointer.checked_add(length).is_none()
            || !(0..length).all(|i| space.translate(pointer + i, W).is_some())
        {
            -14
        } else {
            let size = (length as u64).min(self.extent.length.saturating_sub(self.cursor)) as usize;
            if size == 0 {
                0
            } else {
                let mut staging = [0; MAX];
                staging[..size].copy_from_slice(&before.data[..size]);
                let device = self.device.as_mut().unwrap();
                let old = device.counters();
                let result = device.read_at(self.extent.offset + self.cursor, &mut staging[..size]);
                let new = device.counters();
                counts = Counters {
                    submitted: new.submitted - old.submitted,
                    completed: new.completed - old.completed,
                    notified: new.notified - old.notified,
                };
                status = device.last_status;
                used = device.last_used_len;
                wait = device.last_wait;
                match result {
                    Ok(()) => {
                        for (i, byte) in staging[..size].iter().enumerate() {
                            let pa = space.translate(pointer + i, W).unwrap();
                            unsafe {
                                (pa as *mut u8).write_volatile(*byte);
                            }
                        }
                        self.cursor += size as u64;
                        size as isize
                    }
                    Err(Error::Io) => -5,
                    Err(error) => panic!("fd transport stopped: {:?}", error),
                }
            }
        };
        let after = Snapshot::take(space, pointer, length);
        if returned <= 0 {
            assert!(before == after && self.cursor == position);
        }
        crate::log!(
            "FD_READ seq={} fd={} pointer={:#x} requested={} returned={} pos_before={} pos_after={} submitted={} completed={} notified={} status={} used_len={} polls={} ticks={} prefix_bytes={} before={} after={}\n",
            self.reads,
            fd,
            pointer,
            length,
            returned,
            position,
            self.cursor,
            counts.submitted,
            counts.completed,
            counts.notified,
            status,
            used,
            wait.polls,
            wait.ticks,
            before.length,
            before,
            after
        );
        returned
    }
    pub fn seek(&mut self, fd: usize, offset: i64, whence: usize) -> isize {
        let _gate = Gate::enter();
        let position = self.cursor;
        let pages = memory::stats().1;
        let frames = memory::counters();
        let counts = self
            .device
            .as_ref()
            .map(|d| d.counters())
            .unwrap_or_default();
        let result = if fd != 3 || self.device.is_none() {
            -9
        } else {
            let base = match whence {
                0 => Some(0),
                1 => Some(self.cursor as i64),
                2 => Some(self.extent.length as i64),
                _ => None,
            };
            match base {
                None => -22,
                Some(base) => match base.checked_add(offset) {
                    None => -75,
                    Some(value) if value < 0 => -22,
                    Some(value) => {
                        self.cursor = value as u64;
                        value as isize
                    }
                },
            }
        };
        let after = self
            .device
            .as_ref()
            .map(|d| d.counters())
            .unwrap_or_default();
        assert_eq!(
            (counts.submitted, counts.completed, counts.notified),
            (after.submitted, after.completed, after.notified)
        );
        assert_eq!(frames, memory::counters());
        assert_eq!(pages, memory::stats().1);
        crate::log!(
            "FD_SEEK fd={} offset={} whence={} returned={} pos_before={} pos_after={} submitted=0 completed=0 notified=0 allocated=0 freed=0 pages={}\n",
            fd,
            offset,
            whence,
            result,
            position,
            self.cursor,
            pages
        );
        result
    }
    pub fn close(&mut self, fd: usize, origin: &str) -> isize {
        let _gate = Gate::enter();
        self.closes += 1;
        let used_before = memory::stats().1;
        let mut proof = Wait::default();
        let had = fd == 3 && self.device.is_some();
        let returned = if had {
            let mut device = self.device.take().unwrap(); // revoke before reset
            proof = device
                .close()
                .expect("fd reset unconfirmed; DMA/lease quarantined");
            drop(device);
            assert_eq!(memory::stats().1 + 2, used_before);
            0
        } else {
            -9
        };
        crate::log!(
            "FD_CLOSE seq={} fd={} origin={} returned={} cursor={} had_handle={} reset_confirmed={} reset_polls={} reset_ticks={} dma_freed={} used_before={} used_after={}\n",
            self.closes,
            fd,
            origin,
            returned,
            self.cursor,
            usize::from(had),
            usize::from(had),
            proof.polls,
            proof.ticks,
            if had { 2 } else { 0 },
            used_before,
            memory::stats().1
        );
        returned
    }
    pub fn cleanup(&mut self) {
        if !self.configured {
            return;
        }
        let had = self.device.is_some();
        let used = memory::stats().1;
        if had {
            assert_eq!(self.close(3, "exit"), 0);
        }
        crate::log!(
            "FD_CLEANUP pid=1 had_handle={} dma_freed={} used_before={} used_after={} cursor={} reads={} closed=1\n",
            usize::from(had),
            if had { 2 } else { 0 },
            used,
            memory::stats().1,
            self.cursor,
            self.reads
        );
        self.configured = false;
    }
    pub fn is_closed(&self) -> bool {
        self.device.is_none() && !self.configured
    }
}

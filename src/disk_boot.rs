//! Versioned single-blob container, CPU-owned input and explicit loader handoff.
//! Not a filesystem. Failed/partial transactions never produce an executable slice.
use crate::{
    block::{BlockDevice, Error as BlockError, MAX_READ},
    elf,
    memory::{self, AddressSpace, PAGE},
};
pub const MAX_ELF: usize = 4 * PAGE;

#[derive(Clone, Copy)]
struct Reason(&'static str);
impl core::fmt::Display for Reason {
    fn fmt(&self, out: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for (index, word) in self.0.split_whitespace().enumerate() {
            if index != 0 {
                out.write_str("_")?;
            }
            out.write_str(word)?;
        }
        Ok(())
    }
}

pub struct Loaded {
    pub space: AddressSpace,
    pub entry: usize,
    pub bytes: usize,
    pub extent_header: [u8; 32],
    pub capacity: u64,
    pub payload_offset: u64,
}
struct Input {
    pages: [usize; 4],
    count: usize,
    filled: usize,
    valid: usize,
}
impl Input {
    unsafe fn new() -> Result<Self, &'static str> {
        let mut input = Self {
            pages: [0; 4],
            count: 0,
            filled: 0,
            valid: 0,
        };
        for index in 0..4 {
            let page = unsafe { memory::alloc().map_err(|_| "input_frames")? };
            input.pages[index] = page;
            input.count += 1;
        }
        if !(0..4).all(|i| input.pages[i] == input.pages[0] + i * PAGE) {
            return Err("input_fragmented"); // Drop frees each actual page, never guessed addresses.
        }
        Ok(input)
    }
    fn storage(&mut self) -> &mut [u8] {
        assert_eq!(self.count, 4);
        unsafe { core::slice::from_raw_parts_mut(self.pages[0] as *mut u8, MAX_ELF) }
    }
    fn begin(&mut self) {
        self.valid = 0;
        self.filled = 0;
        self.wipe();
    }
    fn wipe(&mut self) {
        for page in &self.pages[..self.count] {
            for at in 0..PAGE {
                unsafe {
                    ((*page + at) as *mut u8).write_volatile(0);
                }
            }
        }
    }
    fn complete(&mut self, length: usize) {
        assert!(length > 0 && length <= MAX_ELF && self.filled == length);
        self.valid = length;
    }
    fn valid_view(&self) -> Option<&[u8]> {
        (self.valid > 0 && self.valid == self.filled)
            .then(|| unsafe { core::slice::from_raw_parts(self.pages[0] as *const u8, self.valid) })
    }
    fn prefix_precheck(&self) -> &'static str {
        let prefix =
            unsafe { core::slice::from_raw_parts(self.pages[0] as *const u8, self.filled) };
        if elf::validate(prefix).is_ok() {
            "ok"
        } else {
            "rejected"
        }
    }
    fn clear(&mut self) {
        self.begin();
        assert!(self.pages[..self.count].iter().all(|page| {
            (0..PAGE).all(|at| unsafe { ((*page + at) as *const u8).read_volatile() == 0 })
        }));
        crate::log!(
            "DISK_INPUT_CLEAR valid={} filled={} zeroed=1\n",
            self.valid,
            self.filled
        );
    }
}
impl Drop for Input {
    fn drop(&mut self) {
        self.wipe();
        for page in &self.pages[..self.count] {
            unsafe {
                memory::free(*page).unwrap();
            }
        }
    }
}

fn dump(kind: &str, offset: usize, bytes: &[u8]) {
    for (index, chunk) in bytes.chunks(64).enumerate() {
        crate::log!("{} at={} hex=", kind, offset + index * 64);
        for byte in chunk {
            crate::log!("{:02x}", byte);
        }
        crate::log!("\n");
    }
}
fn io(device: &mut BlockDevice, kind: &str, offset: u64, out: &mut [u8]) -> Result<(), BlockError> {
    assert!(out.len() <= MAX_READ);
    let mut previous = [0u8; MAX_READ];
    previous[..out.len()].copy_from_slice(out);
    let before = device.counters();
    let result = device.read_at(offset, out);
    let after = device.counters();
    crate::log!(
        "DISK_IO kind={} offset={} length={} outcome={} status={} used_len={} submitted={} completed={} notified={} buffer_unchanged={}\n",
        kind,
        offset,
        out.len(),
        result.err().map_or("ok", BlockError::token),
        device.last_status,
        device.last_used_len,
        after.submitted - before.submitted,
        after.completed - before.completed,
        after.notified - before.notified,
        usize::from(out == &previous[..out.len()])
    );
    result
}
fn close(device: &mut BlockDevice) {
    let used = memory::stats().1;
    let before = memory::counters();
    let proof = device
        .close()
        .expect("disk reset unconfirmed; keep DMA quarantined and stop");
    assert_eq!(memory::counters().1 - before.1, 2);
    assert_eq!(memory::stats().1 + 2, used);
    crate::log!(
        "DISK_DEVICE_CLOSE reset_confirmed=1 reset_polls={} reset_ticks={} dma_freed=2 used_before={} used_after={}\n",
        proof.polls,
        proof.ticks,
        used,
        memory::stats().1
    );
}
fn release(mut input: Input) {
    input.clear();
    let used = memory::stats().1;
    let before = memory::counters();
    drop(input);
    assert_eq!(memory::counters().1 - before.1, 4);
    crate::log!(
        "DISK_INPUT_RELEASE pages=4 freed=4 used_before={} used_after={}\n",
        used,
        memory::stats().1
    );
}
fn field64(header: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(header[at..at + 8].try_into().unwrap())
}
fn field32(header: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(header[at..at + 4].try_into().unwrap())
}
fn metadata(header: &[u8], capacity: u64) -> Result<(u64, usize), &'static str> {
    let offset = field64(header, 16);
    let length = field64(header, 24);
    let declared = field64(header, 32);
    if &header[..8] != b"ALVXELF\0" {
        return Err("magic");
    }
    if field32(header, 8) != 1 {
        return Err("version");
    }
    if field32(header, 12) != 512 {
        return Err("header_size");
    }
    if length == 0 {
        return Err("zero_length");
    }
    if length > MAX_ELF as u64 {
        return Err("too_long");
    }
    let end = offset.checked_add(length).ok_or("overflow")?;
    if declared > capacity {
        return Err("truncated_container");
    }
    if declared != capacity {
        return Err("container_size");
    }
    if offset < 512 {
        return Err("header_overlap");
    }
    if end > declared {
        return Err("range");
    }
    Ok((offset, length as usize))
}
fn end(
    outcome: &str,
    error: impl core::fmt::Display,
    loader_calls: usize,
    filled: usize,
    valid: usize,
) {
    crate::log!(
        "DISK_END outcome={} error={} loader_calls={} filled={} valid={} remaining_pages={}\n",
        outcome,
        error,
        loader_calls,
        filled,
        valid,
        memory::stats().1
    );
}

pub unsafe fn load(timebase: u64) -> Option<Loaded> {
    assert_eq!(memory::stats().1, memory::KERNEL_TABLE_PAGES);
    crate::log!(
        "DISK_BEGIN format=1 header_bytes=512 max_elf_bytes={} baseline_pages={}\n",
        MAX_ELF,
        memory::KERNEL_TABLE_PAGES
    );
    let mut device = match BlockDevice::open(timebase) {
        Ok(device) => device,
        Err(BlockError::Absent) => {
            end("rejected", "device_absent", 0, 0, 0);
            return None;
        }
        Err(error) => panic!("disk open {:?}", error),
    };
    crate::log!(
        "DISK_DEVICE capacity_bytes={} ring={:#x} bounce={:#x} live_pages={}\n",
        device.capacity(),
        device.ring(),
        device.bounce(),
        memory::stats().1
    );
    let mut header = [0u8; 512];
    if let Err(error) = io(&mut device, "header", 0, &mut header) {
        close(&mut device);
        assert_eq!(error, BlockError::Io);
        end("rejected", "header_ioerr", 0, 0, 0);
        return None;
    }
    dump("DISK_HEADER", 0, &header);
    crate::log!(
        "DISK_META version={} header_bytes={} offset={} length={} container_bytes={} capacity_bytes={}\n",
        field32(&header, 8),
        field32(&header, 12),
        field64(&header, 16),
        field64(&header, 24),
        field64(&header, 32),
        device.capacity()
    );
    let (offset, length) = match metadata(&header, device.capacity()) {
        Ok(meta) => meta,
        Err(error) => {
            close(&mut device);
            end("rejected", error, 0, 0, 0);
            return None;
        }
    };
    let mut input = unsafe { Input::new().expect("bounded contiguous input allocation") };
    // Explicit stale-state injection, not an earlier disk read or executable fallback.
    input.storage().fill(0xa5);
    input.filled = MAX_ELF;
    input.valid = MAX_ELF;
    let old_valid = input.valid;
    input.begin();
    crate::log!(
        "DISK_INPUT pages=4 capacity={} base={:#x} injection=stale_sentinel old_valid={} begin_valid={} begin_filled={} live_pages={}\n",
        MAX_ELF,
        input.pages[0],
        old_valid,
        input.valid,
        input.filled,
        memory::stats().1
    );
    while input.filled < length {
        let at = input.filled;
        let count = (length - at).min(MAX_READ);
        if let Err(error) = io(
            &mut device,
            "payload",
            offset + at as u64,
            &mut input.storage()[at..at + count],
        ) {
            assert_eq!(error, BlockError::Io);
            assert!(input.valid_view().is_none());
            crate::log!(
                "DISK_READ_ABORT filled={} valid={} prefix_precheck={} loader_calls=0\n",
                input.filled,
                input.valid,
                input.prefix_precheck()
            );
            let filled = input.filled;
            close(&mut device);
            release(input);
            end("rejected", "payload_ioerr", 0, filled, 0);
            return None;
        }
        input.filled += count;
        dump("DISK_DATA", at, &input.storage()[at..at + count]);
    }
    input.complete(length);
    crate::log!(
        "DISK_COMPLETE filled={} valid={}\n",
        input.filled,
        input.valid
    );
    close(&mut device); // No loaded AddressSpace exists while this can fail.
    let used_before = memory::stats().1;
    let before = memory::counters();
    let result = unsafe {
        elf::load(
            input
                .valid_view()
                .expect("only complete input reaches loader"),
        )
    };
    let after = memory::counters();
    let loaded = match result {
        Ok((space, entry)) => {
            crate::log!(
                "DISK_LOADER calls=1 outcome=ok error=none allocated={} freed={} used_before={} used_after={} entry={:#x} root={:#x} input_length={}\n",
                after.0 - before.0,
                after.1 - before.1,
                used_before,
                memory::stats().1,
                entry,
                space.root,
                length
            );
            Some(Loaded {
                space,
                entry,
                bytes: length,
                extent_header: header[64..96].try_into().unwrap(),
                capacity: device.capacity(),
                payload_offset: offset,
            })
        }
        Err(error) => {
            // Every loader rejection is contained; adding another validation
            // rule must not turn a malformed disk into a kernel panic.
            let token = Reason(error);
            crate::log!(
                "DISK_LOADER calls=1 outcome=rejected error={} allocated={} freed={} used_before={} used_after={} entry=0 root=0 input_length={}\n",
                token,
                after.0 - before.0,
                after.1 - before.1,
                used_before,
                memory::stats().1,
                length
            );
            assert_eq!(after.0 - before.0, after.1 - before.1);
            release(input);
            end("rejected", token, 1, length, 0);
            return None;
        }
    };
    release(input);
    end("loaded", "none", 1, length, 0);
    loaded
}

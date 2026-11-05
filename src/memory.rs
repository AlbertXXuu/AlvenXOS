pub const PAGE: usize = 4096;
pub const USER_TOP: usize = 0x4000_0000;
pub const R: usize = 2;
pub const W: usize = 4;
pub const X: usize = 8;
pub const U: usize = 16;
pub const KERNEL_TABLE_PAGES: usize = 4;
pub const VIRTIO_VA: usize = 0x9000_1000;
pub const VIRTIO_PA: usize = 0x1000_1000;
pub const VIRTIO_SLOTS: usize = 8;
const V: usize = 1;
const AD: usize = 64 | 128;
const MAX_FRAMES: usize = 32768;

struct Frames {
    start: usize,
    total: usize,
    used: usize,
    high: usize,
    allocations: usize,
    releases: usize,
    bitmap: [u64; MAX_FRAMES / 64],
}
static mut FRAMES: Frames = Frames {
    start: 0,
    total: 0,
    used: 0,
    high: 0,
    allocations: 0,
    releases: 0,
    bitmap: [0; MAX_FRAMES / 64],
};

pub unsafe fn init(start: usize, end: usize) {
    let start = (start + PAGE - 1) & !(PAGE - 1);
    let total = (end & !(PAGE - 1)).checked_sub(start).expect("RAM bounds") / PAGE;
    assert!(total > 0 && total <= MAX_FRAMES);
    unsafe {
        FRAMES.start = start;
        FRAMES.total = total;
    }
}

pub unsafe fn alloc() -> Result<usize, &'static str> {
    let f = unsafe { &mut FRAMES };
    for word in 0..f.total.div_ceil(64) {
        let free_bit = (!f.bitmap[word]).trailing_zeros() as usize;
        let index = word * 64 + free_bit;
        if free_bit < 64 && index < f.total {
            f.bitmap[word] |= 1u64 << free_bit;
            f.used += 1;
            f.allocations += 1;
            f.high = f.high.max(f.used);
            let address = f.start + index * PAGE;
            unsafe {
                core::ptr::write_bytes(address as *mut u8, 0, PAGE);
            }
            return Ok(address);
        }
    }
    Err("out of physical pages")
}

pub unsafe fn free(address: usize) -> Result<(), &'static str> {
    let f = unsafe { &mut FRAMES };
    if address < f.start || address % PAGE != 0 {
        return Err("invalid frame");
    }
    let index = (address - f.start) / PAGE;
    if index >= f.total {
        return Err("frame outside pool");
    }
    let bit = 1u64 << (index % 64);
    if f.bitmap[index / 64] & bit == 0 {
        return Err("double free");
    }
    f.bitmap[index / 64] &= !bit;
    f.used -= 1;
    f.releases += 1;
    Ok(())
}

pub fn stats() -> (usize, usize, usize) {
    unsafe { (FRAMES.total, FRAMES.used, FRAMES.high) }
}

pub fn counters() -> (usize, usize) {
    unsafe { (FRAMES.allocations, FRAMES.releases) }
}

static mut KERNEL_ENTRY: usize = 0;

/// Build immutable shared supervisor tables for the fixed virt RAM layout.
/// Four frames remain resident: root, RAM L1/L0, and MMIO L0.
/// User address spaces never own this shared subtree.
pub unsafe fn init_kernel() -> usize {
    unsafe extern "C" {
        static text_start: u8;
        static text_end: u8;
        static rodata_start: u8;
        static rodata_end: u8;
    }
    let text = core::ptr::addr_of!(text_start) as usize;
    let text_limit = core::ptr::addr_of!(text_end) as usize;
    let rodata = core::ptr::addr_of!(rodata_start) as usize;
    let rodata_limit = core::ptr::addr_of!(rodata_end) as usize;
    let root = unsafe { alloc().unwrap() };
    let level1 = unsafe { alloc().unwrap() };
    let level0 = unsafe { alloc().unwrap() };
    let mmio = unsafe { alloc().unwrap() };
    unsafe {
        KERNEL_ENTRY = (level1 >> 12) << 10 | V;
        table(root)[2] = KERNEL_ENTRY;
        table(level1)[1] = (level0 >> 12) << 10 | V;
        for index in 0..512 {
            let pa = 0x8020_0000 + index * PAGE;
            let flags = if (text..text_limit).contains(&pa) {
                R | X
            } else if (rodata..rodata_limit).contains(&pa) {
                R
            } else {
                R | W
            };
            table(level0)[index] = (pa >> 12) << 10 | V | flags | AD;
        }
        // The first 2 MiB belong to firmware and remain unmapped. The last
        // 2 MiB hold the fixed-board FDT and are read-only; the pool is NX.
        for index in 2..64 {
            let pa = 0x8000_0000 + index * 0x20_0000;
            let flags = if index == 63 { R } else { R | W };
            table(level1)[index] = (pa >> 12) << 10 | V | flags | AD;
        }
        // An alias above USER_TOP keeps MMIO out of private user root[0].
        // root[2]/L1[128] covers 0x90000000; all leaves are S-only RW NX.
        table(level1)[128] = (mmio >> 12) << 10 | V;
        for index in 0..VIRTIO_SLOTS {
            let pa = VIRTIO_PA + index * PAGE;
            table(mmio)[index + 1] = (pa >> 12) << 10 | V | R | W | AD;
        }
    }
    root
}

pub fn kernel_flags(root: usize, address: usize) -> Option<usize> {
    let mut node = root;
    for level in (0..=2).rev() {
        let pte = unsafe { table(node)[(address >> (12 + level * 9)) & 511] };
        if pte & V == 0 {
            return None;
        }
        if pte & (R | X) != 0 {
            return Some(pte & (R | W | X | U));
        }
        node = (pte >> 10) << 12;
    }
    None
}

/// Audit actual leaf PTEs, including physical aliases of immutable text.
pub fn audit(root: usize, text_start: usize, text_end: usize) -> (usize, usize) {
    fn walk(node: usize, level: usize, start: usize, end: usize) -> (usize, usize) {
        let mut result = (0, 0);
        for index in 0..512 {
            let pte = unsafe { table(node)[index] };
            if pte & V == 0 {
                continue;
            }
            if pte & (R | X) == 0 {
                assert!(level > 0);
                let sub = walk((pte >> 10) << 12, level - 1, start, end);
                result.0 += sub.0;
                result.1 += sub.1;
            } else {
                result.0 += usize::from(pte & (W | X) == (W | X));
                let physical = (pte >> 10) << 12;
                let size = 1usize << (12 + level * 9);
                result.1 += usize::from(pte & W != 0 && physical < end && physical + size > start);
            }
        }
        result
    }
    walk(root, 2, text_start, text_end)
}

pub unsafe fn self_test() {
    let a = unsafe { alloc().unwrap() };
    let b = unsafe { alloc().unwrap() };
    assert_ne!(a, b);
    assert_eq!(a % PAGE, 0);
    unsafe {
        (a as *mut usize).write_volatile(0xfeed_cafe);
    }
    unsafe {
        free(a).unwrap();
    }
    assert!(unsafe { free(a) }.is_err());
    assert!(unsafe { free(b + 1) }.is_err());
    let c = unsafe { alloc().unwrap() };
    assert_eq!(a, c);
    assert!((0..PAGE).all(|i| unsafe { ((c + i) as *const u8).read_volatile() == 0 }));
    unsafe {
        free(b).unwrap();
        free(c).unwrap();
    }
    assert_eq!(stats().1, 0);
    crate::log!("TEST frame_allocator PASS aligned_unique_zeroed_reuse_double_free\n");
}

pub struct AddressSpace {
    pub root: usize,
    owned: [usize; 64],
    count: usize,
}

impl AddressSpace {
    pub const fn empty() -> Self {
        Self {
            root: 0,
            owned: [0; 64],
            count: 0,
        }
    }

    unsafe fn frame(&mut self) -> Result<usize, &'static str> {
        if self.count == self.owned.len() {
            return Err("address space page limit");
        }
        let address = unsafe { alloc()? };
        self.owned[self.count] = address;
        self.count += 1;
        Ok(address)
    }

    pub unsafe fn new() -> Result<Self, &'static str> {
        let mut space = Self::empty();
        space.root = unsafe { space.frame()? };
        // Only the lower user tables belong to this address space. The
        // supervisor subtree is shared, immutable and never added to owned.
        unsafe {
            assert_ne!(KERNEL_ENTRY, 0);
            table(space.root)[2] = KERNEL_ENTRY;
        }
        Ok(space)
    }

    pub unsafe fn map(&mut self, va: usize, flags: usize) -> Result<usize, &'static str> {
        if va >= USER_TOP
            || va % PAGE != 0
            || flags & U == 0
            || flags & R == 0
            || flags & (W | X) == (W | X)
        {
            return Err("invalid user mapping");
        }
        let mut node = self.root;
        for level in (1..=2).rev() {
            let index = (va >> (12 + level * 9)) & 511;
            let pte = unsafe { table(node)[index] };
            if pte & V == 0 {
                let child = unsafe { self.frame()? };
                unsafe {
                    table(node)[index] = (child >> 12) << 10 | V;
                }
                node = child;
            } else {
                if pte & (R | W | X) != 0 {
                    return Err("overlapping huge page");
                }
                node = (pte >> 10) << 12;
            }
        }
        let index = (va >> 12) & 511;
        if unsafe { table(node)[index] } & V != 0 {
            return Err("overlapping user segment");
        }
        let physical = unsafe { self.frame()? };
        unsafe {
            table(node)[index] = (physical >> 12) << 10 | V | flags | AD;
        }
        Ok(physical)
    }

    pub fn translate(&self, va: usize, access: usize) -> Option<usize> {
        if va >= USER_TOP {
            return None;
        }
        let mut node = self.root;
        for level in (0..=2).rev() {
            let pte = unsafe { table(node)[(va >> (12 + level * 9)) & 511] };
            if pte & V == 0 {
                return None;
            }
            if pte & (R | X) != 0 {
                if level != 0 || pte & (U | access) != U | access {
                    return None;
                }
                return Some(((pte >> 10) << 12) | (va & (PAGE - 1)));
            }
            node = (pte >> 10) << 12;
        }
        None
    }

    pub fn flags(&self, va: usize) -> Option<usize> {
        kernel_flags(self.root, va)
    }

    pub unsafe fn destroy(&mut self) {
        for address in &self.owned[..self.count] {
            unsafe {
                free(*address).unwrap();
            }
        }
        self.root = 0;
        self.count = 0;
    }
}

unsafe fn table(address: usize) -> &'static mut [usize; 512] {
    unsafe { &mut *(address as *mut [usize; 512]) }
}

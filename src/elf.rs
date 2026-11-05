use crate::memory::{AddressSpace, PAGE, R, U, USER_TOP, W, X};

fn u16_at(data: &[u8], at: usize) -> Result<usize, &'static str> {
    Ok(u16::from_le_bytes(
        data.get(at..at + 2)
            .ok_or("ELF truncated")?
            .try_into()
            .unwrap(),
    ) as usize)
}
fn u32_at(data: &[u8], at: usize) -> Result<usize, &'static str> {
    Ok(u32::from_le_bytes(
        data.get(at..at + 4)
            .ok_or("ELF truncated")?
            .try_into()
            .unwrap(),
    ) as usize)
}
fn u64_at(data: &[u8], at: usize) -> Result<usize, &'static str> {
    let end = at.checked_add(8).ok_or("ELF overflow")?;
    Ok(u64::from_le_bytes(
        data.get(at..end)
            .ok_or("ELF truncated")?
            .try_into()
            .unwrap(),
    ) as usize)
}

/// Validate the entire static RV64 image before allocating any frame.
pub fn validate(data: &[u8]) -> Result<usize, &'static str> {
    if data.get(..7) != Some(&b"\x7fELF\x02\x01\x01"[..]) {
        return Err("ELF identity");
    }
    if u16_at(data, 16)? != 2 || u16_at(data, 18)? != 243 {
        return Err("ELF type or machine");
    }
    if u16_at(data, 54)? != 56 {
        return Err("ELF program header size");
    }
    let entry = u64_at(data, 24)?;
    let phoff = u64_at(data, 32)?;
    let count = u16_at(data, 56)?;
    if count == 0 || count > 32 {
        return Err("ELF program header count");
    }
    if phoff.checked_add(count * 56).ok_or("ELF overflow")? > data.len() {
        return Err("ELF program header range");
    }
    if entry & 1 != 0 {
        return Err("ELF entry alignment");
    }
    let mut executable_entry = false;
    for index in 0..count {
        let at = phoff.checked_add(index * 56).ok_or("ELF overflow")?;
        let kind = u32_at(data, at)?;
        if kind == 3 {
            return Err("dynamic interpreter unsupported");
        }
        if kind != 1 {
            continue;
        }
        let flags = u32_at(data, at + 4)?;
        let offset = u64_at(data, at + 8)?;
        let va = u64_at(data, at + 16)?;
        let filesz = u64_at(data, at + 32)?;
        let memsz = u64_at(data, at + 40)?;
        let end = va.checked_add(memsz).ok_or("ELF virtual overflow")?;
        if filesz > memsz || offset.checked_add(filesz).ok_or("ELF file overflow")? > data.len() {
            return Err("ELF file range");
        }
        if memsz == 0 {
            continue;
        }
        if va < PAGE || end >= USER_TOP - 4 * PAGE || (va & (PAGE - 1)) != (offset & (PAGE - 1)) {
            return Err("ELF virtual range");
        }
        if flags & 4 == 0 || flags & 3 == 3 {
            return Err("ELF permissions");
        }
        if flags & 1 != 0 && entry >= va && entry < end {
            executable_entry = true;
        }
    }
    if !executable_entry {
        return Err("ELF entry is not executable");
    }
    Ok(entry)
}

pub unsafe fn load(data: &[u8]) -> Result<(AddressSpace, usize), &'static str> {
    let entry = validate(data)?;
    let mut space = unsafe { AddressSpace::new()? };
    let result = (|| {
        let phoff = u64_at(data, 32)?;
        for index in 0..u16_at(data, 56)? {
            let at = phoff + index * 56;
            if u32_at(data, at)? != 1 {
                continue;
            }
            let bits = u32_at(data, at + 4)?;
            let offset = u64_at(data, at + 8)?;
            let va = u64_at(data, at + 16)?;
            let filesz = u64_at(data, at + 32)?;
            let memsz = u64_at(data, at + 40)?;
            let flags =
                U | R | (if bits & 2 != 0 { W } else { 0 }) | (if bits & 1 != 0 { X } else { 0 });
            if memsz == 0 {
                continue;
            }
            let mut page = va & !(PAGE - 1);
            while page < va + memsz {
                let pa = unsafe { space.map(page, flags)? };
                let first = page.max(va);
                let last = (page + PAGE).min(va + filesz);
                if last > first {
                    unsafe {
                        core::ptr::copy_nonoverlapping(
                            data.as_ptr().add(offset + first - va),
                            (pa + first - page) as *mut u8,
                            last - first,
                        );
                    }
                }
                page += PAGE;
            }
        }
        unsafe {
            space.map(USER_TOP - PAGE, U | R | W)?;
            space.map(USER_TOP - 2 * PAGE, U | R | W)?;
        }
        Ok(())
    })();
    if let Err(err) = result {
        unsafe {
            space.destroy();
        }
        return Err(err);
    }
    unsafe {
        core::arch::asm!("fence.i");
    }
    Ok((space, entry))
}

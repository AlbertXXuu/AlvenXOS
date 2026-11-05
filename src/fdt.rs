fn be(data: &[u8], at: usize) -> Option<usize> {
    Some(u32::from_be_bytes(data.get(at..at + 4)?.try_into().ok()?) as usize)
}

/// This board parser accepts only bounded FDT blobs in the configured RAM.
pub unsafe fn timebase(address: usize) -> Option<u64> {
    if !(0x8020_0000..0x8800_0000 - 40).contains(&address) {
        return None;
    }
    let header = unsafe { core::slice::from_raw_parts(address as *const u8, 40) };
    if be(header, 0)? != 0xd00d_feed {
        return None;
    }
    let size = be(header, 4)?;
    if !(40..=2 * 1024 * 1024).contains(&size) || address.checked_add(size)? > 0x8800_0000 {
        return None;
    }
    let data = unsafe { core::slice::from_raw_parts(address as *const u8, size) };
    let strings_at = be(data, 12)?;
    let strings = data.get(strings_at..strings_at.checked_add(be(data, 32)?)?)?;
    let struct_at = be(data, 8)?;
    let structure = data.get(struct_at..struct_at.checked_add(be(data, 36)?)?)?;
    let mut cursor = 0;
    while cursor < structure.len() {
        let token = be(structure, cursor)?;
        cursor += 4;
        match token {
            1 => {
                let len = structure.get(cursor..)?.iter().position(|b| *b == 0)?;
                cursor = (cursor.checked_add(len + 1)? + 3) & !3;
            }
            2 | 4 => {}
            3 => {
                let len = be(structure, cursor)?;
                let name = be(structure, cursor + 4)?;
                cursor += 8;
                let value = structure.get(cursor..cursor.checked_add(len)?)?;
                let name_bytes = strings.get(name..)?;
                let name_len = name_bytes.iter().position(|b| *b == 0)?;
                if &name_bytes[..name_len] == b"timebase-frequency" && len == 4 {
                    let hz = be(value, 0)?;
                    return (hz != 0).then_some(hz as u64);
                }
                cursor = (cursor.checked_add(len)? + 3) & !3;
            }
            9 => break,
            _ => return None,
        }
    }
    None
}

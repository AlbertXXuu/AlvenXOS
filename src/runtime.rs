// Local freestanding memory routines; volatile accesses prevent recursive
// lowering of these loops back into compiler-generated libc calls.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcpy(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    for i in 0..n {
        unsafe {
            dst.add(i).write_volatile(src.add(i).read_volatile());
        }
    }
    dst
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memmove(dst: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if dst as usize <= src as usize {
        unsafe {
            memcpy(dst, src, n);
        }
    } else {
        for i in (0..n).rev() {
            unsafe {
                dst.add(i).write_volatile(src.add(i).read_volatile());
            }
        }
    }
    dst
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memset(dst: *mut u8, value: i32, n: usize) -> *mut u8 {
    for i in 0..n {
        unsafe {
            dst.add(i).write_volatile(value as u8);
        }
    }
    dst
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, n: usize) -> i32 {
    for i in 0..n {
        let (left, right) = unsafe { (a.add(i).read_volatile(), b.add(i).read_volatile()) };
        if left != right {
            return left as i32 - right as i32;
        }
    }
    0
}

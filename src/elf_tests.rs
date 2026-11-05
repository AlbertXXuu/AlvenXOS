//! Actual loader failure paths and frame accounting, executed in S mode.
use crate::{arch, elf, memory};

fn word(data: &[u8], at: usize) -> usize {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap()) as usize
}
fn put(data: &mut [u8], at: usize, value: usize) {
    data[at..at + 8].copy_from_slice(&(value as u64).to_le_bytes());
}

pub unsafe fn rollback(original: &[u8], timebase: u64) {
    // Fixed embedded fixture; no heap or host-made success result is involved.
    let mut damaged = [0u8; crate::WORKERS.len()];
    let phoff = word(original, 32);
    let count = u16::from_le_bytes(original[56..58].try_into().unwrap()) as usize;
    let mut loads = [0; 2];
    let mut found = 0;
    for index in 0..count {
        let at = phoff + index * 56;
        if original[at..at + 4] == 1u32.to_le_bytes() {
            assert!(found < loads.len());
            loads[found] = at;
            found += 1;
        }
    }
    assert_eq!(found, 2);
    for (case, error) in [
        ("overlap", "overlapping user segment"),
        ("quota", "address space page limit"),
        ("permissions", "ELF permissions"),
    ] {
        damaged.copy_from_slice(original);
        match case {
            "overlap" => put(&mut damaged, loads[1] + 16, word(original, loads[0] + 16)),
            "quota" => put(&mut damaged, loads[0] + 40, 64 * memory::PAGE),
            "permissions" => {
                damaged[loads[0] + 4..loads[0] + 8].copy_from_slice(&7u32.to_le_bytes())
            }
            _ => unreachable!(),
        }
        if case != "permissions" {
            assert!(
                elf::validate(&damaged).is_ok(),
                "allocation-path fixture must pass validation"
            );
        }
        let used_before = memory::stats().1;
        let before = memory::counters();
        let start = arch::time();
        let observed = match unsafe { elf::load(&damaged) } {
            Err(error) => error,
            Ok((mut space, _)) => {
                unsafe {
                    space.destroy();
                }
                panic!("negative ELF unexpectedly loaded");
            }
        };
        let reject_ticks = arch::time() - start;
        assert_eq!(observed, error);
        let after = memory::counters();
        let allocated = after.0 - before.0;
        let freed = after.1 - before.1;
        let used_after = memory::stats().1;
        assert_eq!(used_before, used_after);
        assert_eq!(allocated, freed);
        if case == "permissions" {
            assert_eq!(allocated, 0);
        } else {
            assert!(allocated > 0);
        }
        if case == "quota" {
            assert_eq!(allocated, 64);
        }
        let recovery_before = memory::counters();
        let start = arch::time();
        let (mut recovered, _) = unsafe { elf::load(original).expect("load after rejection") };
        unsafe {
            recovered.destroy();
        }
        let recovery_ticks = arch::time() - start;
        let recovery_after = memory::counters();
        let recovery_allocated = recovery_after.0 - recovery_before.0;
        let recovery_freed = recovery_after.1 - recovery_before.1;
        let recovered_used = memory::stats().1;
        assert!(recovery_allocated > 0);
        assert_eq!(recovery_allocated, recovery_freed);
        assert_eq!(recovered_used, used_before);
        let error_token = match observed {
            "overlapping user segment" => "overlapping_user_segment",
            "address space page limit" => "address_space_page_limit",
            "ELF permissions" => "ELF_permissions",
            _ => panic!("unrecognized loader error"),
        };
        crate::log!(
            "ELF_ROLLBACK case={} error={} used_before={} used_after={} allocated={} freed={} recovery_allocated={} recovery_freed={} recovered_used={} reject_ticks={} recovery_ticks={} timebase_hz={}\n",
            case,
            error_token,
            used_before,
            used_after,
            allocated,
            freed,
            recovery_allocated,
            recovery_freed,
            recovered_used,
            reject_ticks,
            recovery_ticks,
            timebase
        );
    }
    crate::log!("TEST elf_rollback PASS overlap_quota_permissions_recovery\n");
}

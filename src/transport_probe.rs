//! The same short-circuit register probe is used by real MMIO scanning and
//! host synthetic controls. No register after DeviceID is accessed here.
pub fn is_modern_block(mut read: impl FnMut(usize) -> u32) -> bool {
    if read(0) != 0x7472_6976 {
        return false;
    }
    if read(4) != 2 {
        return false;
    }
    read(8) == 2
}

#[cfg(test)]
mod tests {
    use super::is_modern_block;
    fn observed(magic: u32, version: u32, id: u32) -> (bool, Vec<usize>) {
        let mut reads = Vec::new();
        let result = is_modern_block(|offset| {
            reads.push(offset);
            match offset {
                0 => magic,
                4 => version,
                8 => id,
                _ => panic!("unexpected register"),
            }
        });
        (result, reads)
    }
    #[test]
    fn bad_magic_stops_before_version_and_id() {
        assert_eq!(observed(0, 2, 2), (false, vec![0]));
    }
    #[test]
    fn unsupported_versions_stop_before_id() {
        for version in [0, 1, 3, u32::MAX] {
            assert_eq!(observed(0x74726976, version, 2), (false, vec![0, 4]));
        }
    }
    #[test]
    fn empty_modern_transport_stops_after_id() {
        assert_eq!(observed(0x74726976, 2, 0), (false, vec![0, 4, 8]));
    }
    #[test]
    fn other_modern_devices_are_not_blocks() {
        for id in [1, 3, u32::MAX] {
            assert_eq!(observed(0x74726976, 2, id), (false, vec![0, 4, 8]));
        }
    }
    #[test]
    fn modern_block_is_selected_after_both_checks() {
        assert_eq!(observed(0x74726976, 2, 2), (true, vec![0, 4, 8]));
    }
    #[test]
    fn unsupported_slot_does_not_hide_later_valid_block() {
        let slots = [(0x74726976, 1, 2), (0x74726976, 2, 2)];
        let seen: Vec<_> = slots
            .into_iter()
            .map(|(m, v, i)| observed(m, v, i))
            .collect();
        assert_eq!(seen, vec![(false, vec![0, 4]), (true, vec![0, 4, 8])]);
    }
}

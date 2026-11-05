//! Kernel-side transport/control checks. Image contents are verified independently
//! by the host against actual raw files; no expected disk bytes are in this kernel.
use crate::{
    block::{BlockDevice, Error, MAX_READ, POLL_LIMIT},
    memory,
};

fn dump(id: &str, attempt: usize, bytes: &[u8]) {
    for (chunk, data) in bytes.chunks(64).enumerate() {
        crate::log!(
            "BLOCK_DATA id={} attempt={} at={} hex=",
            id,
            attempt,
            chunk * 64
        );
        for byte in data {
            crate::log!("{:02x}", byte);
        }
        crate::log!("\n");
    }
}
fn read(
    device: &mut BlockDevice,
    id: &str,
    offset: u64,
    length: usize,
    allow_ioerr: bool,
) -> usize {
    let mut out = [0xa5; MAX_READ];
    let mut errors = 0;
    for attempt in 1..=2 {
        out.fill(0xa5);
        let before = device.counters();
        let result = device.read_at(offset, &mut out[..length]);
        let after = device.counters();
        let outcome = result.err().map_or("ok", Error::token);
        let unchanged = usize::from(out[..length].iter().all(|b| *b == 0xa5));
        crate::log!(
            "BLOCK_READ id={} attempt={} offset={} length={} outcome={} device_status={} used_len={} submitted={} completed={} notified={} polls={} ticks={} buffer_unchanged={}\n",
            id,
            attempt,
            offset,
            length,
            outcome,
            device.last_status,
            device.last_used_len,
            after.submitted - before.submitted,
            after.completed - before.completed,
            after.notified - before.notified,
            device.last_wait.polls,
            device.last_wait.ticks,
            unchanged
        );
        assert_eq!(after.submitted - before.submitted, 1);
        assert_eq!(after.completed - before.completed, 1);
        assert_eq!(after.notified - before.notified, 1);
        match result {
            Ok(()) => {
                dump(id, attempt, &out[..length]);
                return errors;
            }
            Err(Error::Io) if allow_ioerr && attempt == 1 => {
                assert_eq!(unchanged, 1);
                errors += 1;
            }
            Err(error) => panic!("block read {}: {:?}", id, error),
        }
    }
    panic!("block recovery failed");
}
fn parameters(device: &mut BlockDevice) {
    let mut out = [0xa5; MAX_READ + 1];
    for (id, offset, length, expected) in [
        ("zero_start", 0, 0, Ok(())),
        ("zero_end", device.capacity(), 0, Ok(())),
        ("zero_oob", device.capacity() + 1, 0, Err(Error::Range)),
        ("oob", device.capacity(), 1, Err(Error::Range)),
        (
            "cross_capacity",
            device.capacity() - 16,
            32,
            Err(Error::Range),
        ),
        ("overflow", u64::MAX - 7, 16, Err(Error::Overflow)),
        ("too_long", 0, MAX_READ + 1, Err(Error::TooLong)),
    ] {
        out.fill(0xa5);
        let before = device.counters();
        let result = device.read_at(offset, &mut out[..length]);
        let after = device.counters();
        assert_eq!(result, expected);
        assert_eq!(before.submitted, after.submitted);
        assert_eq!(before.notified, after.notified);
        assert_eq!(before.completed, after.completed);
        assert!(out.iter().all(|b| *b == 0xa5));
        crate::log!(
            "BLOCK_PARAMETER id={} offset={} length={} outcome={} submitted=0 completed=0 notified=0 buffer_unchanged=1\n",
            id,
            offset,
            length,
            result.err().map_or("ok", Error::token)
        );
    }
}
fn opened(device: &BlockDevice, generation: usize) {
    assert!(
        device.capacity() >= 30 * 512,
        "controlled read scenario needs at least 30 sectors"
    );
    assert_eq!(memory::stats().1, memory::KERNEL_TABLE_PAGES + 2);
    crate::log!(
        "BLOCK_OPEN generation={} physical={:#x} capacity_bytes={} sector_bytes=512 queue_size={} features={:#x} ring={:#x} bounce={:#x} budget_ticks={} poll_limit={} live_pages={}\n",
        generation,
        device.physical(),
        device.capacity(),
        crate::block::QUEUE_SIZE,
        device.negotiated_features(),
        device.ring(),
        device.bounce(),
        device.budget_ticks(),
        POLL_LIMIT,
        memory::stats().1
    );
}
fn owner_busy(device: &BlockDevice, timebase: u64, id: &str) {
    let frames = memory::counters();
    let before = device.counters();
    assert!(matches!(BlockDevice::open(timebase), Err(Error::Busy)));
    let after = device.counters();
    assert_eq!(memory::counters(), frames);
    assert_eq!(before.submitted, after.submitted);
    assert_eq!(before.completed, after.completed);
    assert_eq!(before.notified, after.notified);
    crate::log!(
        "BLOCK_OWNER id={} outcome=busy allocated=0 freed=0 submitted=0 completed=0 notified=0\n",
        id
    );
}
pub unsafe fn run(timebase: u64) {
    let baseline = memory::stats().1;
    let allocations = memory::counters();
    assert_eq!(baseline, memory::KERNEL_TABLE_PAGES);
    let mut device = match BlockDevice::open(timebase) {
        Ok(device) => device,
        Err(Error::Absent) => {
            assert_eq!(memory::counters(), allocations);
            crate::log!(
                "BLOCK_ABSENT scanned_slots=8 submitted=0 allocated=0 freed=0 remaining_pages={}\n",
                baseline
            );
            crate::log!("TEST block_transport PASS absent_contained\n");
            return;
        }
        Err(error) => panic!("block init: {:?}", error),
    };
    opened(&device, 0);
    owner_busy(&device, timebase, "live");
    read(&mut device, "head", 0, 32, false);
    let io_errors = read(&mut device, "far_a", 7 * 512, 512, true);
    read(&mut device, "far_b", 29 * 512, 512, false);
    read(&mut device, "cross", 509, 800, false);
    read(&mut device, "max_window", 1, MAX_READ, false);
    let capacity = device.capacity();
    read(&mut device, "last_sector", capacity - 512, 512, false);
    read(&mut device, "last_byte", capacity - 1, 1, false);
    parameters(&mut device);
    let mut out = [0xa5; 16];
    let before = device.counters();
    assert_eq!(device.injected_timeout(0, &mut out), Err(Error::Timeout));
    assert!(out.iter().all(|b| *b == 0xa5));
    let after = device.counters();
    assert_eq!(after.submitted - before.submitted, 1);
    assert_eq!(after.notified - before.notified, 1);
    assert_eq!(after.completed - before.completed, 0);
    assert!(
        device.last_wait.ticks >= device.budget_ticks() || device.last_wait.polls == POLL_LIMIT
    );
    crate::log!(
        "BLOCK_TIMEOUT injection=hide_used outcome=timeout offset=0 length=16 submitted=1 completed=0 notified=1 polls={} ticks={} budget_ticks={} poll_limit={} buffer_unchanged=1\n",
        device.last_wait.polls,
        device.last_wait.ticks,
        device.budget_ticks(),
        POLL_LIMIT
    );
    assert_eq!(device.read_at(0, &mut out), Err(Error::Poisoned));
    assert_eq!(device.counters().submitted, after.submitted);
    assert_eq!(device.counters().completed, after.completed);
    assert_eq!(device.counters().notified, after.notified);
    assert!(out.iter().all(|b| *b == 0xa5));
    crate::log!(
        "BLOCK_PARAMETER id=poisoned offset=0 length=16 outcome=poisoned submitted=0 completed=0 notified=0 buffer_unchanged=1\n"
    );
    let proof = device
        .close()
        .expect("reset timed-out device before freeing DMA");
    assert_eq!(memory::stats().1, baseline);
    crate::log!(
        "BLOCK_CLOSE generation=0 reset_confirmed=1 reset_polls={} reset_ticks={} remaining_pages={}\n",
        proof.polls,
        proof.ticks,
        memory::stats().1
    );
    let first = device.counters();
    let mut recovery = BlockDevice::open(timebase).expect("reopen after timeout reset");
    opened(&recovery, 1);
    drop(device); // A closed old handle must not revoke a newer owner's lease.
    owner_busy(&recovery, timebase, "after_closed_drop");
    read(&mut recovery, "after_timeout", 0, 64, false);
    let second = recovery.counters();
    // This is a healthy device entering close, not the already-poisoned read-timeout path.
    assert!(matches!(
        recovery.injected_reset_timeout(),
        Err(Error::ResetTimeout)
    ));
    assert_eq!(memory::stats().1, baseline + 2);
    owner_busy(&recovery, timebase, "quarantined");
    assert!(
        recovery.last_reset_wait.ticks >= recovery.budget_ticks()
            || recovery.last_reset_wait.polls == POLL_LIMIT
    );
    crate::log!(
        "BLOCK_RESET_TIMEOUT injection=hide_reset_ack outcome=reset_timeout polls={} ticks={} budget_ticks={} poll_limit={} retained_pages=2 live_pages={}\n",
        recovery.last_reset_wait.polls,
        recovery.last_reset_wait.ticks,
        recovery.budget_ticks(),
        POLL_LIMIT,
        memory::stats().1
    );
    assert_eq!(recovery.read_at(0, &mut out), Err(Error::Poisoned));
    assert_eq!(recovery.counters().submitted, second.submitted);
    assert_eq!(recovery.counters().completed, second.completed);
    assert_eq!(recovery.counters().notified, second.notified);
    assert!(out.iter().all(|b| *b == 0xa5));
    crate::log!(
        "BLOCK_PARAMETER id=quarantined offset=0 length=16 outcome=poisoned submitted=0 completed=0 notified=0 buffer_unchanged=1\n"
    );
    let proof = recovery.close().expect("final reset before DMA release");
    crate::log!(
        "BLOCK_CLOSE generation=1 reset_confirmed=1 reset_polls={} reset_ticks={} remaining_pages={}\n",
        proof.polls,
        proof.ticks,
        memory::stats().1
    );
    let after = memory::counters();
    assert_eq!(after.0 - allocations.0, 4);
    assert_eq!(after.1 - allocations.1, 4);
    assert_eq!(memory::stats().1, baseline);
    crate::log!(
        "BLOCK_SUMMARY reads_ok=8 device_errors={} injected_timeouts=1 injected_reset_timeouts=1 submitted={} completed={} notified={} allocated=4 freed=4 remaining_pages={} quarantined=0\n",
        io_errors,
        first.submitted + second.submitted,
        first.completed + second.completed,
        first.notified + second.notified,
        baseline
    );
    crate::log!("TEST block_transport PASS reads_controls_reset_recovery\n");
}

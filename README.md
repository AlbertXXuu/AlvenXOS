# AlvenX OS

[简体中文](README.zh-CN.md)

A small RV64 kernel developed in Rust and RISC-V assembly for explainable, reproducible systems experiments. Milestone: **0.6.0 / stage03d**. Real disk-loaded user programs execute in QEMU; this is not a general Linux-compatible OS.

| Status | Result |
| --- | --- |
| Development checks | PASS for the controlled stage03d increment |
| Independent technical acceptance | PASS for the fixed implementation and documented scope |
| User console experience | WAITING_USER |
| Public release | Local preparation only; license, attribution and contest decisions remain open |

## Capabilities and limits

OpenSBI boot; page allocation/reclamation; Sv39 spaces; kernel RX/R/RW and user RX/NX/guard checks; integer trap context; timer/yield scheduling; read-only modern VirtIO MMIO with an exclusive lease and confirmed reset before DMA release; disk ELF loading without embedded fallback; task-private preopened fd3 with bounded read, close, exit cleanup and signed lseek SET/CUR/END.

Supported target: fixed QEMU virt, RV64, 128 MiB, one hart, one read-only modern block device. No paths/openat/VFS/general filesystem, general exec/wait, dynamic linker, signals, SMP, user floating-point/vector context or full Linux/POSIX ABI. Physical exhaustion and natural device-failure recovery remain unproven. See [milestone facts](docs/MILESTONE.md).

## Build and run

Verified host: Windows + WSL2 Ubuntu 24.04. Other hosts are unverified. Execution is QEMU system emulation, not a host unit test.

Existing dependencies: Rust nightly-2025-05-20 with riscv64gc-unknown-none-elf, GNU RISC-V binutils 2.42 (riscv64-linux-gnu-as/ld), Python 3.12, QEMU 8.2.2. Observed default firmware: OpenSBI 1.3. No third-party Cargo crates or Python packages are required by this workflow.

In the existing WSL Ubuntu shell, from this repository:

```bash
bash scripts/build.sh
python3 -B scripts/check_seek.py --scenario seek-data-a --positive-repeat 1
```

Necessary stage03d incremental matrix:

```bash
python3 -B scripts/check_seek.py --positive-repeat 3
```

Eight scenarios run three times: seek A/B, exit cleanup, unaligned extent, backend EIO, and affected read/close/EIO regressions in the new kernel. Successful checks exit 0; QEMU exit 0 alone is insufficient. Each command creates a new build/result directory. Inspect the printed results.json and scenario run-1.log. Hex records contain actual syscall bytes. The console runs automatically and exits; there is no interactive shell or GUI. User presentation review remains pending.

Build uses cargo --locked --offline. A new machine must already have the listed toolchain/components. Scripts do not install software or change system settings. Cache defaults to the WSL home; ALVENX_TARGET_DIR selects an alternative. Source/artifact changes require a new build. Use check_seek.py for the 0.6 artifact layout; older runners keep their frozen rules.

Both a Git checkout and a source-only export can use these commands. A checkout records its actual revision and status. An export without its own `.git` records `git_metadata_mode=source-export`, unavailable Git metadata, and null revision/status; it does not claim a clean checkout or inherit a parent repository's identity. Source, controlled-input, tool and artifact hashes remain required in either mode. Do not initialize a dummy repository to build an export.

## Project map

| Entry | Purpose |
| --- | --- |
| src/, user/ | Kernel and self-checking user assembly |
| scripts/ | Build, generated controlled media, versioned parsers and host checks |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Architecture and dated scope evolution |
| [SOURCES.md](SOURCES.md) | Dependencies, applicable notices and contest disclosure |
| [Milestone](docs/MILESTONE.md) | Fixed version, evidence anchors and limits |
| [Publishing](docs/PUBLISHING.md) | Candidate files, history boundary and release decisions |
| [Requirements](docs/REQUIREMENTS.md) | Verified regional rules and AlvenX standards mapping |
| [Portfolio](PORTFOLIO.md) | Engineering work and attribution limits |
| build/, results/ | Ignored local artifacts; never automatically public |

Historical reports retain their original wording/status. Local evidence is not bundled with a source-only candidate; reviewers can regenerate controlled inputs and runs.

## Publication and contest

This is a locally reviewable milestone candidate, **not an authorized public release**. No source license has been chosen and no license grant is implied. Contributor identity, attribution, documentation licensing and full-history publication require confirmation. Cargo publish=false only controls Cargo publication.

The verified regional category is Operating Systems Principles, kernel implementation direction. GitHub preparation does not replace contest GitLab submission. The technical plan requires source open licensing and documentation CC-BY-SA 4.0; these grants have not been applied on the owner's behalf. AI-use policy remains unconfirmed. See [requirements and gaps](docs/REQUIREMENTS.md).

Guest virtual ticks and host wall time are not hardware latency, storage throughput, official scores or a superiority claim.

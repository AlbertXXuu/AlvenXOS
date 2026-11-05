# 依赖与参赛披露 / Dependencies and contest disclosure

## 依赖 / Dependencies

Cargo.lock仅包含alvenx-core；Rust core随nightly-2025-05-20工具链提供，许可见[Rust COPYRIGHT](https://github.com/rust-lang/rust/blob/master/COPYRIGHT)及其MIT/Apache文本。构建和运行使用GNU RISC-V binutils、Python、QEMU 8.2.2与OpenSBI；这些工具和固件分别适用其自身许可，源码候选不附带它们的安装包或源码。

Cargo.lock contains only alvenx-core. Rust core is supplied by the pinned toolchain. External build tools and firmware retain their own licenses; their installers and source trees are outside the candidate.

## 技术依据 / Technical basis

| 范围 / Area | 采用的接口或技术内容 / Interface or technical content |
| --- | --- |
| 特权级、页表与固件 / Privilege, paging and firmware | [RISC-V Supervisor ISA](https://docs.riscv.org/reference/isa/v20260120/priv/supervisor.html)与[SBI v3.0](https://docs.riscv.org/reference/sbi/v3.0/binary-encoding.html)：Sv39、CSR、异常、sret及固件调用约定 |
| 块设备 / Block device | [Virtio 1.2](https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html)：modern MMIO、split ring、只读块接口、屏障和reset；[QEMU 8.2.2 virtio-blk](https://github.com/qemu/qemu/blob/v8.2.2/hw/block/virtio-blk.c)用于核对IOERR的used length行为 |
| 受控故障 / Controlled failure | [QEMU 8.2.2 blkdebug](https://github.com/qemu/qemu/blob/v8.2.2/docs/devel/blkdebug.txt)：后端EIO注入配置 |
| 系统调用接口 / Syscall interface | Linux v6.6 [unistd.h](https://github.com/torvalds/linux/blob/v6.6/include/uapi/asm-generic/unistd.h)与[errno-base.h](https://github.com/torvalds/linux/blob/v6.6/include/uapi/asm-generic/errno-base.h)：接口编号和错误码；具体支持范围见[里程碑](docs/MILESTONE.md) |

## 提交前核定 / Before submission

按赛事I.2-I.3，实际复制内容须在对应位置及设计文档/PPT中总体说明；实际复制或借鉴的代码、技术内容及实际基础版本、自主增量应在参赛材料中披露。保留适用许可证要求的声明，参赛设计与PPT中的集中披露清单仍待完成。

Under I.2-I.3, mark actually copied content at its use sites and explain it overall in the design/PPT. Disclose actual copying or technical borrowing, the actual base version and project increments in contest materials. Retain applicable license notices. The consolidated contest disclosure remains to be prepared.

源码许可、文档CC-BY-SA 4.0授权范围、作者与队伍贡献、AI规则及披露仍待确认。候选范围和公开授权事项见[发布范围](docs/PUBLISHING.md)与[规则映射](docs/REQUIREMENTS.md)。

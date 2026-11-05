# AlvenX OS 独立内核实施范围

2026-11-04起的架构演进记录。当前能力和固定运行条件见[里程碑](docs/MILESTONE.md)。

## 本轮实现与验收顺序

1. S 模式启动：OpenSBI 交接、独立启动汇编、BSS、栈、SBI 控制台与关机；在真正 QEMU system 模式下启动。
2. 内存基础：固定 QEMU virt / RV64 / 128 MiB 平台，4 KiB 物理页分配和回收；Sv39 根页表与用户映射；核对对齐、唯一性、零填充、重复释放拒绝。
3. 用户态：自己解析静态 RV64 ELF、映射 PT_LOAD 和用户栈；自己保存/恢复整数寄存器、切换页表；U 态 ecall 实现 write、exit、getpid、yield。
4. 调度与隔离：每任务独立用户页表，同一 VA 对应不同 PA；轮转 yield 和 SBI timer 抢占；非法用户指针返回 EFAULT，读取 supervisor 页触发真实页故障且其他任务存活。
5. 可量化检查：固定模拟参数，分别记录宿主墙钟与 guest virtual time；在相同内核中比较不同长度的 yield 工作负载，保留三次冷启动原始日志。无官方分数、真机周期或完整 Linux 兼容性声明。

## 边界与后续迁移

首轮使用内核只读区中的实际 ELF 字节作为加载输入，不提供磁盘驱动或文件系统。先验证特权级、页表和完整现场，再逐步引入块设备、文件 I/O及进程功能。

上述为首轮边界。03b已完成受控磁盘ELF→用户write/exit并独立验收；03c增量是每Task私有只读extent的fd3，在非重入S态handler内同步read及close/exit清理。输入页/用户页/设备DMA的所有权分开；单设备租约不共享，全目标预检后IO，成功才copyout/推进游标。此桥接不提供路径、openat/VFS、通用FS或fork/exec；阶段新规则与固定工件见STAGE-03C.md。

内核高权限区采用 RAM 身份映射且 U=0，各用户根页表共享该 supervisor 映射；低地址的用户代码、数据和栈使用 U 页。trap 在同一身份映射下访问内核栈，切换任务后写 satp 并全量 sfence.vma。单 hart，内核 handler 不重入；首轮不提供内核可阻塞调用或 SMP 安全性。

新源码、用户程序与宿主编排工具分别组织；宿主脚本检查 ELF 和运行日志，只有 qemu-system-riscv64 中的独立内核结果可计入功能验收。所有阶段区分通过、失败和未实现。

## 阶段 02 的增量

kernel root、一个 L1 表和一个 L0 表永久保留，用户地址空间只拥有自己的 root、低地址表和用户页。内核所在的首个 2 MiB 使用 4 KiB 叶页区分 RX/R/RW；其余物理池采用 RW NX 的 2 MiB 叶页。固定 FDT 区为 R；当前入口显式要求 QEMU 128 MiB 布局及 DTB=0x87e00000，链接器限制内核小于 0x80400000。

受控 S 态故障仅在调度开始前进行，通过一次性 guard 匹配 cause、原始 PC 和 stval，并使用独立的汇编 resume 标签恢复。S 态恢复保留原 kernel sp 并清 sscratch；其他 S 异常仍关机失败。用户权限故障仅终止对应任务。加载中途失败释放 owned 清单，不能递归释放共享子树。具体结果与剩余限制见 STAGE-02.md。

## 阶段 03a 的增量

共享 root[2]/L1[128] 增加一个 L0，建立 MMIO alias 0x90001000→0x10001000，共 8 个 S-only RW NX 页，避免与用户 root[0] 冲突。0.3.0 常驻表页固定为 4。块操作目前在用户调度前完成，单队列、单在途请求、有界轮询；AtomicBool 租约禁止第二个句柄重置活动设备，关闭后旧句柄销毁不会解除新句柄的租约。

queue/header/status 与 bounce 各占一个临时物理页。设备完成后才从 bounce 复制；参数拒绝和错误保持调用者缓冲不变。开始 close 即撤销提交能力；reset 未确认则隔离 DMA 和设备租约，不能重用或释放，只有再次观察 status=0 才回收。真实 reset 无法确认且不能恢复时安全失败，不能称已回收通过。具体场景、注入与运行证据见 STAGE-03A.md。

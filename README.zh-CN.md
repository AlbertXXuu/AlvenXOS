# AlvenX OS

[English](README.md)

使用 Rust 与 RISC-V 汇编逐步实现的小型 RV64 内核，面向可解释、可复现的系统实验。当前里程碑 **0.6.0 / stage03d** 已在 QEMU 中运行真实磁盘用户程序，尚非通用 Linux 兼容系统。

| 状态 | 结论 |
| --- | --- |
| 开发检查 | stage03d 受控增量通过 |
| 独立技术验收 | 固定实现与明确范围 PASS |
| 用户终端体验 | 等待用户验收 |
| 公开发行 | 仅本地准备；许可、署名和赛事事项待决 |

## 能力与限制

已实现 OpenSBI 启动、物理页分配回收、Sv39 空间、内核 RX/R/RW 和用户 RX/NX/guard、整数异常现场、timer/yield 调度、只读 modern VirtIO MMIO 独占租约及 reset 确认后释放 DMA、无嵌入回退的磁盘 ELF 加载，以及 Task 私有预打开 fd3 的 read、close、退出清理和 signed lseek SET/CUR/END。

固定条件为 QEMU virt、RV64、128 MiB、单 hart、单只读 modern 块设备。尚无路径/openat/VFS/通用文件系统、通用 exec/wait、动态链接、信号、SMP、用户浮点/向量保存或完整 Linux/POSIX ABI。物理耗尽与自然设备故障恢复未证明。见[里程碑事实](docs/MILESTONE.md)。

## 构建与运行

已验证宿主为 Windows + WSL2 Ubuntu 24.04，内核运行于 QEMU system。其他宿主尚未验证。

现有依赖：Rust nightly-2025-05-20 及 riscv64gc-unknown-none-elf、GNU RISC-V binutils 2.42（riscv64-linux-gnu-as/ld）、Python 3.12、QEMU 8.2.2；实测默认固件 OpenSBI 1.3。此工作流无第三方 Cargo crate 或 Python 包依赖。

在已有 WSL Ubuntu 中进入本仓库：

```bash
bash scripts/build.sh
python3 -B scripts/check_seek.py --scenario seek-data-a --positive-repeat 1
```

03d 必要增量矩阵：

```bash
python3 -B scripts/check_seek.py --positive-repeat 3
```

八场景各三次，包括 seek A/B、未 close 退出、不对齐 extent、后端 EIO，以及新内核中的 read/close/EIO 回归。检查成功退出 0；QEMU 自身退出 0 不足以证明通过。每次新建编号目录，查看脚本打印的 results.json 和场景 run-1.log；hex 字段保存真实 syscall 字节。当前自动运行后退出，无交互 shell 或 GUI；终端展示等待用户验收。

构建采用 cargo --locked --offline，新机器须预先具备所列工具和组件。脚本不安装软件、不改系统设置。缓存默认在 WSL 用户目录，ALVENX_TARGET_DIR 可指定替代位置。源码或工件变化后重新构建；当前 0.6 使用 check_seek.py，旧 runner 保留原工件规则。

Git checkout和无Git源码导出均可直接执行上述命令。前者记录真实版本和状态；后者在自身无.git时明确记录source-export、元数据不可用、revision/status为null，不冒称干净仓库、不借用父仓库身份。两种模式都必须记录源码、输入、工具和工件哈希，不需要初始化虚假仓库。

## 阅读与目录

| 入口 | 职责 |
| --- | --- |
| src/、user/ | 内核和自检用户汇编 |
| scripts/ | 构建、受控介质、分版解析器及宿主检查 |
| [ARCHITECTURE.md](ARCHITECTURE.md) | 架构与按阶段保留的演进 |
| [SOURCES.md](SOURCES.md) | 依赖、适用声明及参赛披露 |
| [里程碑](docs/MILESTONE.md) | 固定版本、证据锚点和限制 |
| [发布范围](docs/PUBLISHING.md) | 候选文件、历史边界及待决项 |
| [规则映射](docs/REQUIREMENTS.md) | 区域赛原文与 AlvenX 标准 |
| [工程档案](PORTFOLIO.md) | 工程工作及署名边界 |
| build/、results/ | 忽略的本地生成物，不默认公开 |

历史阶段报告保留当时原文和状态。原始证据保留本地，不随源码候选整体打包；审查者可重新生成输入并复现。

## 发布与参赛

当前是本地可审查的 GitHub 里程碑候选，**尚未获得公开发行授权**。源码许可证未选，本说明不授予许可；贡献者身份、署名、文档授权及完整历史公开范围待确认。Cargo publish=false 只控制 Cargo 发布。

本轮核实类别为“操作系统原理赛道”的“内核实现方向”。GitHub 准备不能代替赛事 GitLab 提交。技术方案要求源码采用开源协议、文档采用 CC-BY-SA 4.0，本轮没有替权利人实施授权。AI 使用规则仍待确认。见[规则与缺口](docs/REQUIREMENTS.md)。

guest 虚拟时间和宿主墙钟不解释为硬件时延、存储吞吐、官方分数或全面领先。

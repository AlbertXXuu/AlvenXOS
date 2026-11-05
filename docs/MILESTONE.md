# Milestone facts / 里程碑事实

Local milestone **0.6.0 / stage03d**, checked 2026-11-05. This is not a published Release or an official contest score. / 本地里程碑，不是已发布 Release 或赛事成绩。

| Item / 项目 | Fixed fact / 固定事实 |
| --- | --- |
| Runtime implementation / 运行源码 | `2681ba9a31fc893e8f6778caac951806adff3ced` |
| Accepted documentation / 已验收文档 | `f8031acfd747d6036a6c99e0aa14f3a0d679d0c1` |
| Main local build / 本地主构建 | `build/20261104T180718Z-352` |
| Kernel SHA-256 | `6fdbd8b33280657e3e12c713e35a5955f1ce721892f4faf0db8faa3c38650193` |
| Development matrix / 开发矩阵 | 8 scenarios x 3 cold boots = 24 real QEMU runs |
| New seek protocol / 新 seek 协议 | 230 host cases; separate from kernel executions |
| Independent technical review / 独立技术验收 | PASS for controlled signed lseek and affected read/close/EIO; no findings |
| User console / 用户终端 | WAITING_USER |

Same kernel and disk ELF, different A/B data extents: 22 seeks, 9 data-bearing reads, 99 written bytes and user exit 92. Other scenarios cover exit cleanup, unaligned data and one backend EIO injection. Actual read bytes are bound to the medium; task counters, return values and final four resident pages are checked. / 同一内核和磁盘ELF仅换A/B数据，实际随机回读及write绑定介质字节；另测退出清理、非对齐和一次后端EIO，最终恢复四页常驻基线。

Two local builds had 56 equal bound artifacts. Independent review rebuilt the kernel and ten user ELFs with equal bytes, reran the 24 incremental boots, and sampled real guest registers/memory/queue/allocator state. Old full 03c matrices were not rerun. / 两次本地构建56项一致；独立验收完成重建、24次增量启动及真实客户机采样，未重跑旧03c全矩阵。

## Local evidence, not bundled / 本地证据，不随源码候选打包

Paths below are relative to the **workspace** unless stated otherwise. They are local references, not public download links:

- `evidence/acceptance-stage03d-20261104T181013013Z/review.json`, SHA-256 `be65342ba67ca42c4b3816e46a67afb3dcf2ccfbb1b99da2ad8363b98d2b3da8`.
- `native/results/stage03d-bound-run/results.json` and its scenario logs.
- `native/results/stage03d-host-final/regression.json`.
- `native/results/stage03d-handoff/handoff.json` and `manifest.json`.
- Native build source/tool/controlled-media records: `build/20261104T180718Z-352/inputs.json` and `SHA256SUMS`.

A source candidate contains reproducible generators and checkers, not these raw records. A public evidence summary must be approved separately, keep hashes/conditions, remove private paths and identify unavailable raw evidence. / 源码候选仅附生成器和检查器；公开证据摘要需单独批准、保留哈希与条件、处理本机路径并说明原始记录可用性。

## Limits / 限制

Fixed RV64 QEMU virt, 128 MiB, single hart, one read-only modern device and a controlled preopened task. No general filesystem/VFS/openat, exec/wait, dynamic linker, signals, SMP or user floating-point/vector state. Natural device-failure recovery and physical exhaustion are not established. Guest virtual time is not hardware latency or storage performance. / 固定平台、单设备受控任务；未实现通用文件/进程ABI，未证明自然故障和物理耗尽可恢复，不将虚拟时间解释为硬件性能。

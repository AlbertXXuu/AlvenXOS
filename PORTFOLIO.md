# Engineering record / 工程档案

This describes supported project work, not a personal resume claim. / 以下是项目事实，不代替个人履历或作者认定。

- Problem: make the RV64 user-mode and storage lifecycle explainable and verifiable with real execution. / 目标：真实验证用户态与存储生命周期。
- Project decisions: incremental standalone kernel, explicit ownership of ELF input/user pages/DMA, versioned protocols and host image-byte binding. / 决策：分阶段自编内核、明确页/设备所有权、分版协议与字节绑定。
- Difficult corrections: native parser false positives, fixed resident-page baselines, VirtIO transport read ordering and partial-ELF validity. / 本项目难点：解析器误判、常驻页基线、VirtIO传输读取顺序及部分ELF有效长度。
- Supported result: stage03d controlled lseek/read/close/EIO scope passed development and independent technical review. No official score, production reliability or external adoption is established. / 当前受控范围技术通过，无官方成绩或已证实外部采用。
- Limits and next decision: see [milestone](docs/MILESTONE.md); formal contest design/teaching contribution and defense material remain to prepare. / 后续完善参赛设计、教学价值与答辩材料。
- Attribution: this repository was developed in an AI-assisted collaboration. Team ownership, human decisions/contributions, author/contact metadata and applicable contest AI disclosure require confirmation. Do not convert assistant-produced implementation into an unsupported personal-authorship claim. / AI协作实现；队伍权属、个人贡献、署名联系信息和赛事AI披露要求待核实。

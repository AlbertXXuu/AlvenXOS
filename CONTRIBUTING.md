# Contribution notes / 协作说明

The project is experimental and its public license/author policy is unresolved. Coordinate rights and intended use with the owner before distributing modifications. No contributor license agreement or rights transfer is created here. / 实验项目，公开许可和作者政策待决；本文不创设授权转让。

For a reproducible bug report, record the source commit, supported host/tool versions, exact build/run command, input hashes, expected behavior and actual raw log. Do not include credentials, personal paths or large private media in public reports. / 问题报告记录版本、环境、命令、输入哈希、预期与实际；不公开秘密或大型私有介质。

Use [README](README.md) / [中文入口](README.zh-CN.md) for the current workflow. Keep runtime changes minimal, retain failed runs, and distinguish host checks from real QEMU execution. Source changes require rebuilding. Documentation-only changes use link/path/diff/publication-boundary checks rather than rerunning a frozen kernel matrix. / 按影响验证，保留失败，区分宿主与内核运行。

# Requirements and gaps / 规则及待决映射

Checked 2026-11-05. This maps verified text to the local milestone; it is not an organizer approval or a legal compliance certificate. / 本轮原文核对及项目映射，不代表组委会批准或法律合规结论。

## Regional contest / 华东区域赛

Official [OS Principles page](https://course.educg.net/pages/contest/contest.jsp?contestCID=0&contestID=PC8qM6iMTU0&my=false&tabDocID=10291997) identifies the regional competition as independent of the national competition. The kernel implementation direction is inside OS Principles, not a substitute national kernel track. The unrelated HarmonyOS page is not used as evidence.

Official [technical plan](https://gitlab.eduxiji.net/csc1/csc-os/os2026-regional/os2026-east-china-region/-/blob/main/2026%E5%B9%B4%E6%93%8D%E4%BD%9C%E7%B3%BB%E7%BB%9F%E8%AE%BE%E8%AE%A1%E8%B5%9B%E5%8D%8E%E4%B8%9C%E5%8C%BA%E5%9F%9F%E8%B5%9B%E6%8A%80%E6%9C%AF%E6%96%B9%E6%A1%88-1010.pdf?ref_type=heads), 5 pages, local audit copy SHA-256 `87aa31339caf043bc3d6a740c0aa735a2bd6411cfd6cedb370ef98555d47571d`, 215306 bytes. Local workspace audit: `evidence/publication-audit-20261104T182137Z/official-source.json`. This original PDF is not included in the candidate archive.

| Verified section / 原文位置 | Requirement / 要求 | Current mapping / 当前映射 |
| --- | --- | --- |
| p1 I.1, I.5(1) | Select a published topic; kernel construction may use hardware or a simulator / 选题，小型内核可用模拟器 | RV64 QEMU milestone; actual registered topic/team confirmation pending / 实际选题队伍待确认 |
| p1 I.2-I.3 | Mark actually copied content at its use sites; disclose actual copying or technical borrowing, the actual base version and own increments in the design/PPT / 实际复制内容在对应位置注明；设计/PPT说明实际复制或借鉴的代码、技术内容及实际基础版本、自主增量 | Technical basis is recorded in SOURCES; consolidated contest design/PPT disclosure remains to be completed / 技术依据已登记，参赛设计与PPT集中披露仍待完成 |
| p1 I.4 | Source under an open-source license; documentation CC-BY-SA 4.0 / 源码开源协议、文档指定许可 | Both rights decisions pending; no grants applied automatically |
| p2-p3 II.1 | Reference weights: code30, docs30, teaching10, engineering10, demo/defense20 / 参考评分权重 | Technical validation is not a contest score; teaching/design/defense packaging incomplete |
| p3 III.1(1) | Complete commented engineering files, design document, process/history / 完整工程、设计及过程资料 | Source/build/check workflow present; stage history retained; formal contest design and contribution chapter pending |
| p4 III.1(4) | Public code/docs on contest hosting platform / 托管平台公开 | Pending licensing, identity and explicit upload authorization |
| p5 IV.1 | Develop in GitLab and submit its project link / GitLab项目提交 | GitHub preparation alone does not satisfy this requirement |

The website displays a 10/15 09:19 to 12/24 23:59 interval; verify the live registration/submission state and timezone with the team. The technical PDF does not state that interval. No AI-use clause was found in these five pages; absence is not permission or prohibition. Ask the organizer for the applicable rule. / 页面时间与PDF区分；AI规则未见，仍须向组委会确认。

## Applicable AlvenX standards / AlvenX适用通用标准

Read-only sources in the separate private control workspace `D:\.Development\AlvenX`; full planning documents are not redistributed:

- README.md + workspace.json: layout revision `2026-10-26.1`.
- foundation/strategy/FOUNDATION.md: `v2.11.0`, 2026-10-26, section4 general decision principles.
- projects/README.md: independent project Git/dependencies/test/ignore rules, no declared version.
- operations/planning/GOVERNANCE.md: revision `2026-09-26.1`, sections1/2/7/8; general evidence, DoD, distribution and portfolio requirements.

Exact source hashes are recorded in the local audit. Agent/UI-specific architecture, licenses, branding and schedules are not imposed on this no-GUI kernel.

| Applicable principle / 适用原则 | Evidence or gap / 落地与缺口 |
| --- | --- |
| Specific user need; minimum sufficient result / 需求与最小交付 | This documentation/maintenance task prepares a reviewable milestone, adds no runtime capability |
| Independent Git, dependencies, tests, ignores / 独立项目边界 | native has its own Git, Cargo/toolchain files, build/check entry and generated-output exclusions |
| Clear source/artifact separation / 源码与生成物分离 | src/user/scripts/docs vs ignored build/results; outer private comparison dirs classified without moving |
| Frozen evidence and bounded claims / 固定证据、适当主张 | Original stages/reviews unchanged; three acceptance states and controlled QEMU limits explicit |
| Documentation verification / 文档验收 | Link/path, command-static, archive/history boundary and source/license checks; no kernel matrix rerun for docs |
| Portfolio attribution / 工程档案 | PORTFOLIO records technical work, AI assistance and unknown personal attribution/external use |
| Workspace registration / 工作区登记 | AlvenXOS remains at its authorized original path, outside the registered AlvenX projects layout; registration/exception decision pending, no silent move or external workspace edit |

English/Chinese entry points implement the user's explicit requirement. Neither these mappings nor another AlvenX project's Apache license authorize this project's public release.

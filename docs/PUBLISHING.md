# Local publication scope / 本地发布范围

Status: **candidate prepared locally; public distribution is blocked by unresolved decisions**. No remote, repository, upload, tag or Release is authorized by this document. / 仅本地候选；本文不授权远程、上传、打标签或发行。

## Candidate boundary / 候选边界

The reviewed source candidate is the committed native tree after `.gitattributes` export exclusions: src/, user/, scripts/, Cargo.toml/lock, rust-toolchain.toml, linker.ld, .gitignore/.gitattributes, the two READMEs, ARCHITECTURE.md, SOURCES.md, PORTFOLIO.md, CHANGELOG.md, CONTRIBUTING.md, SECURITY.md and docs/. The audit records the exact file names and hashes; those records, not this category list, define the prepared snapshot.

候选按native提交树及export-ignore筛选，准确文件列表/哈希以本次本地审计为准。构建脚本自行生成受控介质；不需要上传本机已有镜像。

Excluded and retained locally: sibling kernel/ and its Git history, baselines/, full archives, evidence/, build/, results/, toolchains, caches, virtual environments, original media, large logs and personal configuration. Historical STAGE reports, agent instructions and parser-fix narratives remain in native Git history/local working tree, but are excluded from the source-only archive. / 旧仓库、完整归档、原始证据和生成物均保留本地；历史stage、协作指令和修复叙事仍在Git历史/工作树，源码候选导出时排除。

**Git history is a separate publication surface.** `.gitignore` does not remove tracked files or earlier commits. `export-ignore` affects git archive, not clone/push. A future full-history push requires its own review and authorization. The candidate folder is not a new Git repository, and publishing it must not silently substitute for the original development history required by the contest.

**Git历史需单独决定公开范围。** ignore不消除已跟踪内容，export-ignore不影响push；不能把筛选源码包冒充完整参赛开发历史。

## Decisions before public distribution / 公开前待决

1. Source license and rights-holder approval; no license has been selected or granted. / 源码许可与权利人确认。
2. Documentation licensing: regional rules require CC-BY-SA 4.0; confirm rights and scope before applying a grant. / 文档授权及适用范围。
3. Team identity, authorship, contributor attribution and AI-assisted contribution disclosure. No personal contribution or school/team identity is inferred. / 队伍、作者、贡献和AI协助披露。
4. Organizer confirmation of AI policy and actual registered topic/platform requirements. / AI政策、实际选题和平台要求。
5. Review exact files, all reachable history, contact metadata and any optional evidence summary. Pattern scanning is bounded and cannot establish absence of secrets. / 文件、历史、身份元数据及证据复审；扫描不保证绝对无秘密。
6. Destination and action authorization: GitHub milestone and contest GitLab submission are distinct. / GitHub与赛事GitLab分别授权。

Cargo publish=false is not a GitHub license or distribution authorization. No source LICENSE or documentation license grant was added during this preparation.

## Export-build correction / 导出构建修复

The original 75-file candidate at 0fde13d failed independent build review: provenance.py required `git status` even though the archive intentionally omitted `.git`. That candidate and its failed build remain preserved and are not relabeled as passed. The corrected candidate explicitly supports source-export metadata with null Git identity/status while retaining complete hashes and normal checkout drift checks. / 原0fde13d候选首审P2及失败保留；新候选修复无Git来源记录，旧包不改写成通过。New export build/smoke and guard evidence is recorded separately in the midterm handoff.

## Recoverable cleanup / 可恢复整理

Original directories and reference paths stay unchanged. Fixed builds/logs/reviews, unique failures and the old dirty checkout are not cleanup targets. WSL caches/toolchains may be active and are not touched. Existing pycache files may be referenced by preservation manifests; they are retained. This round found no justified safe deletion/move target. The navigation is the classification index; no migration occurred and no recovery operation is needed. / 本轮未发现值得执行且安全的冗余清理对象，因此不为整理而搬迁；无不可恢复删除，无旧资料重新压缩。

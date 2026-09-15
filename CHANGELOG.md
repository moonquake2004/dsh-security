# Changelog

本文件记录面向使用者的变更。安全检查的**判定语义是公开契约的一部分**，故新增检查、判定翻转、严重度调整都算 MINOR。

发布规则见 [`dsh-doctor` 的 CHANGELOG](https://github.com/moonquake2004/dsh-doctor/blob/main/plugin/CHANGELOG.md#发布规则--release-policy)：新增检查/子命令 → MINOR；判定或语义变化 → MINOR 且逐条写明；纯修复 → PATCH。

---

## [0.5.0] — 2026-09-15

### Added

- **SR5 纳入浏览器凭据材料**（社区 #6720 实测）：报告者遇到 agent 自行开启 Goal 后"读取、复制 Chrome 相关 Profile 数据，并尝试寻找可复用的登录状态"。此前我们的凭据库模式只有 `.credentials.yaml` / `id_rsa` / `.env` / `.npmrc` / `security.json`，**浏览器凭据不在其中**。
  - 两档判据：① 浏览器 profile 目录（`Google/Chrome`、`Chromium`、`BraveSoftware`、`Microsoft Edge`、`Firefox/Profiles`）——高信号；② 凭据文件名但**要求前面有路径分隔符**（`/Cookies`、`\Login Data`、`logins.json`、`cookies.sqlite`、`key3/4.db`、`Local State`），以免把 HTTP 头与正文里的 "Cookie" 当路径。
  - 对照样例（`curl -H "Cookie: …"`、正文 grep "Cookies"）保持 pass，无误报。

### Changed — ⚠️ 行为变更

- 同上：**此前通过 SR5 的会话可能因新增检出面而变为失败**。这正是本仓库把"新增检查/判定变化"放在 MINOR 位的原因（见发布规则）。

## [0.4.5] — 2026-09-15

### Fixed

- **SP5 的 rc 语义误报**（社区 #6678 @ciceroyang 指出，我们用真 node-semver 逐例复核确认正好踩了）：原实现直接调 `satisfies(..., { includePrerelease: false })`，于是 `>=0.1.0-rc.5 <0.2.0` 面对 `0.1.5-rc.2` 返回 false —— **把健康插件报成"不支持当前核心"**。这正是本仓库 `SECURITY.md` 里定义为漏洞的那类假阳性。
  - `install-tree.checkRange` 重写为**三态 + rc 规则**：区间含任何预发布比较器 → 按数值判定（接受 `0.1.5-rc.2`，拒绝越界者）；纯 release 区间面对预发布安装版本 → `unknown`；SP5 只对 `unsatisfied` 生成发现。
  - 返回 `state: satisfied | unsatisfied | unknown`；新增 3 条 rc 回归用例（含两条"**不得**误报"）。

## [0.4.4] — 2026-09-15

### Fixed

- **SP14 的路径分隔符（真实平台缺陷）**：`PROMPT_DIR_HINT` 只认 `/`，而 Windows 上 `path.join` 产出反斜杠 → **一个注入内容文件都收集不到，整套提示注入检测在该平台形同虚设**。由 CI 加入 windows-latest 后首次运行抓出。现同时接受两种分隔符，并加 Windows 回归用例。
- 5 处平台相关测试：install-tree / SP13 `inferDshHome` 断言硬编码 POSIX 字面量（改用 `join()`）；SP1 ×3（PATH 桩是 POSIX shell 脚本，Windows 不可执行，检查正确报 PM_NOT_FOUND）；SP3 ×2（检查**有意**在 Windows 跳过 danger-full-access 结论）。

### Infra

- **CI 覆盖 ubuntu + windows × Node 22/24**。

## [0.4.3] — 2026-09-15

### Added

- **SP12 识别"用户层整值覆盖"**：Cordis patch 的 `config` 是整值替换且后写获胜，用户为同一 id 写完整 `config` 即让 bundle 里的 `__jsExpr` 节点不入配置树（表达式永不求值）。此后 SP12 区分"暴露中"与"已被静态值消除"，并在插件升级后提示复核覆盖是否仍有效。含 3 条用例（整值覆盖 / 仅覆盖无关 id / 只给 disabled 不给 config）。

## [0.4.2] — 2026-09-15

### Changed

- **SR5 严重度校准**：读取凭据库是链条**前置信号**而非利用，且操作者核验问题时也会合法读取 → 读取定 **MEDIUM**（浮现于报告但不影响退出码），仅**写入/篡改**定 CRITICAL。避免把"提示"做成"阻断"。

## [0.4.1] — 2026-09-15

### Added

- **SP15 依赖来源可验证性**（生态审计 G5）：区分 registry（可核对 integrity/provenance）与 git/tarball/本地（不可核对）。**精度修正**：初版只看 `package.json` 会把 `github:user/repo` 一律判"未锁定"，实测本机 lockfile 已固定到具体 commit → 加 lockfile 判定，只有"两处都查不到"才判 HIGH。

## [0.4.0] — 2026-09-15

### Added

- **SP14 提示注入面检测**（威胁调研的生态空白能力）：扫"会被模型读到的文本"（skills / prompts / presets）。A 级硬信号＝不可见 Unicode / 凭据外泄**指令**（动词+密文+目的地三段式）/ 静默执行指令；B 级仅计数＝"忽略先前指令"类措辞（合法安全技能本就会这么写）。
  - **误报修正**：初版 A2 只要求"密钥"与"http"在 120 字符内共现，把真实 profile 文档里的**配置示例**报成凭据外泄 → 收紧为三段式并加回归用例。

## [0.3.0] — 2026-09-15

### Added

- **SR5 宿主凭据库访问检测**（源自 #6465 的沙箱绕过链条）：命中读取 `.credentials.yaml` 等真实凭据库、或工作区外私钥材料即报；`.npmrc` / `settings.yaml` / `security.json` 等**配置载体仅在写入时**才报（读取属正常排障）。
- **`SECURITY.md`**：报告渠道（本仓库已开启 GitHub 私有漏洞报告）、范围（把**假阴性**与**高噪声假阳性**明确列为漏洞——本项目最严重的历史故障正是"检查因格式漂移静默失配却报 clean"）、以及我们自身的协调披露实践。

### Fixed

- **运行时检查的自噪**（影响 SR1–SR5 / SS1–SS4）：原扫"最新会话"通常就是**当前正在写入的会话**，会把操作者自己的操作报成发现（实测：SR1 的 critical 全是本会话里自己写的测试串）。改为默认取 mtime 早于活跃窗口的最新会话。
- **SR1/SR2 收窄到高信号规则**：SR1 只留逃逸原语，SR2 只留提权原语；裸 `sudo`/`chmod`/写 `/tmp`/读 `/etc` 属日常活动 → 只计数不报。
- **SP9 的修复建议**：核实 `ensureSymlink` 对指向别处的链接会 `unlink` 后重建（`dsh-app-boot:407-427`）→ 断链**重启即自愈**；`rm -rf` 整目录既不必要又有风险（heal 只重建安装闭包，不重建第三方 scope）。

## [0.2.0] — 2026-09-11

### Fixed（P0：会话形态漂移导致的运行时安全层失效）

- **会话定位器世代感知**：原只认 `session.jsonl[.zstd]`，导致 SR/SS 全在分析另一个工作区的**过期日志**。现认 `session.v<N>.jsonl[.zstd]`（v3 为当前世代）。
- **归一化 `extractEvent`**：v3 真实形态是 `tool/call.data.arguments`（JSON **字符串**）、结果在 `data.message.content[].content[].text`（**嵌两层**）、callId 在 `data.message.source.callId`。
- **解除 5 项失明/误报**：SR1/SR2/SR3/SS3 原本**永不匹配**（字段不存在）；SS4 因配对键错误 **100% 误报**（真实 0 孤儿报成 45 个）。
- **4 个 EXT-\* 集成修复**：poison-guard 读错字段（真发现报成通过）、reducer 契约、sandbox-audit **退役**（npm 从未发布）、ecosystem 陈旧门控。**未安装的工具改为有理由 skip**，不再从报告里消失。
- **误报止血**：SS2 加数字边界 + 排除回环/私网/保留网段、裸 IP 降为信息级；SL1/SL4 常态信号降为信息级；SP8 加**影响门控**（0.1.5 profile 不再从 registry 装 `@deepseek-ai/*`）。

### Added（P1/P2）

- **修复 4 项失效检查**：SP1（`npm audit` 在 pnpm 上 `ENOLOCK` → 永久假 PASS）、SP3（原扫 profile 内的 patch，无一含 sandbox-policy → 死代码）、SP5（字符串启发式 → 读真实能力面）、SP9（前提反转 + 对 symlink 失明）。
- **新增 3 项**：SP11（patch 层覆盖安全行）、SP12（`!!js` 配置即代码，实机抓到两个已装插件在用）、SP13（Code Mode × 沙箱错配 #3245）。

## [0.1.7] 及更早

早期版本请见 git 历史。要点：`dsh-security` 的 SP/SR/SL/SS 四层检查框架与 `dsh-doctor --security` 集成。

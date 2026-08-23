# dsh-security 设计文档

> 状态：0.1.x 实现基线（2026-08-19 复审修复后与代码对齐）。
> 本文档是 README 架构图的落地细节版；两者冲突时以本文为准并修 README。

## 目标

DSH 生态统一安全检查层：任何工具都能贡献检查，用户一键获得完整安全态势。
覆盖插件全生命周期：发现 → 安装 → 运行 → 更新 → 退役。

## 分层

| 层 | 检查 | 输入 | 说明 |
|---|---|---|---|
| Layer 0 协议 | Severity / CheckPhase / SecurityCheck 接口 | — | 5 级严重度 × 4 阶段；`pass/fail/skip` 三种结果 |
| Layer 1 静态 | SP1-SP7, SS1-SS3 | profile 目录 / 会话日志文件 | 安装前后审计 |
| Layer 2 运行时 | SR1-SR4 | 会话日志文件（明文或 zstd） | 基于会话日志分析 |
| Layer 3 生命周期 | SL1-SL4 | profile 目录 + npm registry | 版本/integrity/信誉/兼容 |
| 外部集成 | EXT-PG-1 / EXT-SA-1 / EXT-ECO-1 / EXT-RED-1 | 各外部工具 | PATH 探测，缺失即 skip |

## 核心契约

### 结果语义
- `ok=true, skipped=false`：通过。
- `ok=false`：失败；severity 决定退出码贡献。
- `skipped=true`（`ok=true`）：**因外部条件未真正执行**（网络不可达、依赖工具缺失、低于 severityThreshold）。必须带原因（detail），不计入失败统计，不影响退出码。对齐 #1719 r5 词汇表「skip 必须带 reason」。
- **禁止 fail-open**：查询失败 ≠ 无风险。网络类检查全部查询失败时必须返回 skip，而不是"未发现问题"的 pass。

### 退出码
| exitCode | 含义 |
|---|---|
| 0 | 全部通过，或只有 MEDIUM/LOW/INFO 级失败 |
| 1 | 有 HIGH 级失败 |
| 2 | 有 CRITICAL 级失败 |

### 配置（~/.dsh/security.json）
仅在调用方显式 `registry.setConfig(loadConfig())` 后生效；未注入 = 全部启用。
```json
{ "enabled": true, "checks": { "SR1": { "enabled": false } }, "severityThreshold": "medium" }
```
`severityThreshold` 把低于阈值的失败降级为 skip。

## 与 dsh-doctor 的上下文映射约定

doctor 的 `--security` 是本框架的主要宿主。contextFn 按 check 分发：
- SP*/SL*/EXT-*（静态/生命周期）→ profile 目录
- SR*/SS*（运行时/会话）→ 最新会话日志文件路径
  - 布局：`~/.dsh/sessions/<user>/<session>/session.jsonl[.zstd]`（两层目录，与 doctor S11 一致）
  - .zstd 由框架内部经 `zstd -dc` 解压；二进制缺失时检查返回 skip

## 安全边界

- Plugin Interface（`<dir>/checks.d/*.json` 注册外部命令检查）：只在调用方显式传入目录时加载；JSON 中的 command 会被 shell 执行，该目录等同配置文件信任级。
- 外部集成探测只用 `which <bin>`；不使用 `npx <pkg>` 探测/兜底（避免探测行为本身触发任意包下载执行）。
- SS1/SS2 输出对凭据/PII 掩码（前缀 + 长度），检测器自身不在报告中泄露敏感内容。
- 外部命令执行一律 `execFileSync(cmd, args)` 数组形式，不做字符串拼接。

## 已知边界（非 bug，记录取舍）

- SP1 的 npm audit 在 pnpm profile 上因无 package-lock 通常走跳过分支（detail 如实说明）；pnpm 侧漏洞覆盖由 SL1 lockfile-integrity + SP6 OSV 补位。
- SP7（client 语法预检，#2752 补充案例）：对已装 DSH 插件包（package.json 含 `dsh` 字段门控，避免误扫普通依赖）的 client 产物（`client/*.js|mjs`、`lib/client.js`、根级 `client.js`）逐个执行 `node --check`（Node ≥22 自动探测 ESM/CJS）。解析失败 = boot 前可断定的白屏源 → HIGH。上限：每包 10 文件、60 插件包、全局 200 文件；上限只约束真插件，普通依赖不占额。
- SR 系列是正则启发式，存在误报可能；只扫 tool/call（SR3 凭据类额外扫 result），阈值偏保守。
- EXT-ECO-1 的关键词计数（breaking/critical 提及数）是弱信号，固定 LOW 级提示性输出。

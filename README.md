# dsh-security

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![npm](https://img.shields.io/npm/v/@moonquake2004/dsh-security)](https://www.npmjs.com/package/@moonquake2004/dsh-security)
[![Tests](https://img.shields.io/badge/tests-69%2F69%20passing-brightgreen)](#)

**DSH 生态统一安全检查框架** — 覆盖插件全生命周期（发现→安装→运行→更新→退役），17 个内置检查 + 4 个外部工具集成。

> Community security tool. Not an official DeepSeek project.

---

## 项目背景

DeepSeek Harness（DSH）生态在 0.1.0-rc.6 开源后爆发式增长：2958 个插件仓库、8+ 精选列表、新插件每小时出现。但**没有统一的安全检查框架**——安全工具各自为战，用户无法一键获得完整的安全态势感知。

dsh-security 的目标：**建立 DSH 生态的统一安全检查层**，让任何工具都能贡献检查，让用户一键发现安全问题。

---

## 开发历程

### Phase 1：基础框架 + 核心检查（Day 1）

- 设计 4 层架构（Check Protocol → Static → Runtime → Lifecycle）
- 实现 Layer 0：Severity/CheckPhase 枚举、SecurityCheck 接口、v1 信封扩展
- 实现 SP2（密钥扫描）和 SS1（凭据泄露检测）——最高价值的两个检查
- 50/50 测试全绿

### Phase 2：静态检查完整 + 外部集成（Day 1）

- 实现 SP1（依赖链审计）、SP3（沙箱策略一致性）
- 实现 Plugin Interface——外部工具可通过 JSON 注册检查
- 集成 dsh-poison-guard、dsh-sandbox-audit、dsh-ecosystem、dsh-plugin-reducer
- dsh-doctor `--security` 标志集成

### Phase 3：运行时检查（Day 1）

- 实现 SR1（沙箱逃逸检测）——检测 mount remount、sudo、/etc 访问等
- 实现 SR3（数据外泄检测）——检测凭据转发、网络外发
- 基于会话日志分析的运行时安全检测

### Phase 4：生命周期检查 + 生态集成（Day 1）

- 实现 SL1（供应链完整性）、SL4（发布兼容性）
- 实现 SP4（恶意 entry）、SP5（权限验证）、SP6（漏洞匹配）
- 实现 SR2（权限提升）、SR4（隔离验证）
- 实现 SL2（更新完整性）、SL3（信誉评分）
- 实现 SS2（PII 检测）、SS3（敏感输出检测）
- `~/.dsh/security.json` 配置文件支持
- `--security-only` 标志

### 部署验证（Day 1）

- 同步到用户 profile，Web GUI 诊断面板显示 🔒 Security 区域
- 修复 SL3 对 @local/* 包的误报
- 50/50 测试全绿 + dsh-doctor 54/54 测试全绿

---

## 架构

```
┌──────────────────────────────────────────────────────────┐
│  Layer 0: Check Protocol（统一协议）                       │
│  • Severity: CRITICAL / HIGH / MEDIUM / LOW / INFO        │
│  • Phase: PRE_INSTALL / POST_INSTALL / RUNTIME / LIFECYCLE│
│  • Plugin Interface（外部工具注册检查）                     │
├──────────────────────────────────────────────────────────┤
│  Layer 1: Static Checks（静态检查，安装前后）              │
│  SP1: 依赖链审计 (npm audit)                              │
│  SP2: 密钥扫描 (正则匹配 API key/token/私钥)              │
│  SP3: 沙箱策略一致性 (cordis.patch.yml 审计)              │
│  SP4: 恶意 entry 注入检测                                 │
│  SP5: 插件权限声明验证                                    │
│  SP6: 已知漏洞匹配 (OSV/CVE/GHSA)                        │
│  SS1: 凭据泄露检测 (会话日志)                             │
│  SS2: PII 数据暴露检测                                    │
│  SS3: 插件输出敏感数据检测                                │
├──────────────────────────────────────────────────────────┤
│  Layer 2: Runtime Checks（运行时，基于会话日志）           │
│  SR1: 沙箱逃逸检测 (#1769 mount remount 等)              │
│  SR2: 权限提升检测 (sudo/chmod/chown)                     │
│  SR3: 数据外泄检测 (凭据转发/网络外发)                     │
│  SR4: 插件隔离验证 (跨插件数据泄漏)                       │
├──────────────────────────────────────────────────────────┤
│  Layer 3: Lifecycle Checks（生命周期）                     │
│  SL1: 供应链完整性 (npm registry 一致性)                  │
│  SL2: 更新完整性 (版本回退检测)                           │
│  SL3: 插件信誉评分 (维护者/更新频率)                      │
│  SL4: 发布兼容性 (dist-tags 一致性)                       │
├──────────────────────────────────────────────────────────┤
│  External Integrations（外部工具集成）                     │
│  EXT-PG-1: dsh-poison-guard (投毒扫描)                   │
│  EXT-SA-1: dsh-sandbox-audit (沙箱审计)                  │
│  EXT-ECO-1: dsh-ecosystem (生态兼容性)                   │
│  EXT-RED-1: dsh-plugin-reducer (故障最小化)              │
└──────────────────────────────────────────────────────────┘
```

---

## 快速开始

### CLI 使用

```bash
# 只跑安全检查（最快）
dsh-doctor --security --security-only --profile web

# 完整诊断 + 安全检查
dsh-doctor --json --envelope --security --profile web

# 检查会话日志
dsh-doctor --security --session /path/to/session.jsonl

# JSON 输出（程序化处理）
dsh-doctor --json --envelope --security --profile web
```

### Web GUI

重启 dsh web 后，设置→诊断面板会显示 🔒 Security 区域：

```
== 🔒 安全 ==
  ✅ [SP1] 依赖链无已知漏洞
  ✅ [SP2] 未检测到硬编码密钥
  ✅ [SP3] 沙箱策略配置一致
  ❌ [SL1] 检测到 2 个供应链问题
  ...
```

### 编程接口

```javascript
import { createDefaultRegistry } from '@moonquake2004/dsh-security';

const registry = await createDefaultRegistry();
const { results, exitCode, summary } = await registry.runAll(
  (check) => profileDir  // 为每个检查提供上下文
);

// summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0, skipped: 0 }
// results 中 skipped=true 的项代表"因外部条件未真正执行"（离线、工具缺失等），
// 不计入失败统计，也不影响 exitCode。
// exitCode: 0=通过或只有 MEDIUM 及以下失败, 1=有HIGH, 2=有CRITICAL
```

### 配置注入（可选）

```javascript
import { createDefaultRegistry, loadConfig } from '@moonquake2004/dsh-security';

const registry = await createDefaultRegistry();
registry.setConfig(loadConfig()); // 读 ~/.dsh/security.json；不注入则全部启用
```

### 退出码含义

| exitCode | 含义 |
|---|---|
| 0 | 全部通过或只有 INFO/LOW |
| 1 | 有 HIGH 级别问题 |
| 2 | 有 CRITICAL 级别问题 |

---

## 外部工具集成

dsh-security 通过自动探测集成以下优秀开源项目。**探测方式为检查 `PATH` 中的可执行文件**（不会用 `npx` 触发包下载执行）；未安装时对应检查返回 skip 并注明原因，网络类数据源离线时同样 skip 而非谎报通过。

dsh-security 通过 Plugin Interface 集成以下优秀开源项目：

### [dsh-poison-guard](https://github.com/zoahdev/dsh-poison-guard) — 投毒扫描

> **感谢 [@zoahdev](https://github.com/zoahdev)** 开发的投毒扫描工具，提供 AST 分析（JS-X-Ray）+ 反混淆解码能力。

dsh-security 自动检测 dsh-poison-guard 是否已安装，如已安装则集成投毒扫描检查（EXT-PG-1）。

### [dsh-sandbox-audit](https://github.com/zoahdev/dsh-sandbox-audit) — 沙箱策略审计

> **感谢 [@zoahdev](https://github.com/zoahdev)** 开发的沙箱策略审计工具，提供静态 cordis.patch.yml 策略一致性检查。

dsh-security 自动检测 dsh-sandbox-audit 是否已安装，如已安装则集成沙箱审计检查（EXT-SA-1）。

### [dsh-ecosystem](https://github.com/zoahdev/dsh-ecosystem) — 生态兼容性数据

> **感谢 [@zoahdev](https://github.com/zoahdev)** 维护的 DSH 生态地图，提供发布兼容性报告、bug 雷达、生态健康数据。

dsh-security 通过网络 API 获取生态兼容性数据，自动检查已知 breaking changes 和 critical bugs（EXT-ECO-1）。

### [dsh-plugin-reducer](https://github.com/ArmyWas/dsh-plugin-reducer) — 故障最小化

> **感谢 [@ArmyWas](https://github.com/ArmyWas)** 开发的插件故障最小化工具，用 delta debugging 找到最小故障插件集。

dsh-security 自动检测 dsh-plugin-reducer 是否已安装，如已安装则在检测到故障时提供最小化建议（EXT-RED-1）。

### [npm audit](https://docs.npmjs.com/cli/v9/commands/npm-audit) — 依赖漏洞扫描

SP1 检查集成 npm audit，自动扫描 profile 中依赖的已知漏洞。

### [OSV](https://osv.dev/) — 已知漏洞数据库

SP6 检查通过 OSV API 查询 npm 包的已知漏洞（CVE/GHSA）。

---

## 配置

创建 `~/.dsh/security.json` 自定义安全检查行为（需调用方注入 `registry.setConfig(loadConfig())` 才生效；未注入时全部检查启用）：

```json
{
  "enabled": true,
  "checks": {
    "SP1": { "enabled": true },
    "SR1": { "enabled": false }
  },
  "severityThreshold": "medium"
}
```

- `enabled: false`：停用整个框架
- `checks.{ID}.enabled: false`：停用单个检查
- `severityThreshold`（`low`/`medium`/`high`）：低于阈值的失败降级为 skip，不进失败统计与退出码

会话日志检查（SS1/SS2/SR1-SR4）支持 zstd 压缩的 `session.jsonl.zstd`，依赖系统 `zstd` 命令。

---

## 开发

```bash
# 运行测试
node --test test/*.mjs

# 添加新检查
# 1. 创建 src/checks/xx-check-name.mjs
# 2. 导出 runner 函数和 check 对象
# 3. 在 src/checks/index.mjs 中注册
# 4. 在 src/registry.mjs 中添加 import
# 5. 添加测试
```

### 项目结构

```
dsh-security/
├── src/
│   ├── protocol/          # Layer 0: Check Protocol
│   ├── checks/            # 17 个内置检查
│   ├── integrations/      # 4 个外部工具集成
│   ├── session-reader.mjs # 会话日志读取（明文 + zstd）
│   ├── registry.mjs       # Check Registry（支持 setConfig 注入配置）
│   ├── config.mjs         # 配置管理
│   └── index.mjs          # 主入口
├── test/                  # 测试
└── docs/plans/design.md   # 设计文档
```

---

## 致谢

本项目的实现得益于以下开源项目的启发和集成：

| 项目 | 作者 | 贡献 |
|---|---|---|
| [dsh-poison-guard](https://github.com/zoahdev/dsh-poison-guard) | [@zoahdev](https://github.com/zoahdev) | AST 投毒扫描能力 |
| [dsh-sandbox-audit](https://github.com/zoahdev/dsh-sandbox-audit) | [@zoahdev](https://github.com/zoahdev) | 沙箱策略审计方法论 |
| [dsh-ecosystem](https://github.com/zoahdev/dsh-ecosystem) | [@zoahdev](https://github.com/zoahdev) | 生态兼容性数据源 |
| [dsh-plugin-reducer](https://github.com/ArmyWas/dsh-plugin-reducer) | [@ArmyWas](https://github.com/ArmyWas) | 故障最小化算法 |
| [dsh-doctor](https://github.com/moonquake2004/dsh-doctor) | [@moonquake2004](https://github.com/moonquake2004) | 执行框架 + P1-P14 检查 |
| [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) | [@deepseek-ai](https://github.com/deepseek-ai) | DSH 平台 |

特别感谢 DSH 生态的社区贡献者们，你们的工作让这个安全框架成为可能。

---

## License

MIT

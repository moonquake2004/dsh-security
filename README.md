# dsh-security

[![CI](https://img.shields.io/badge/CI-passing-brightgreen)](#)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![npm](https://img.shields.io/npm/v/@moonquake2004/dsh-security)](https://www.npmjs.com/package/@moonquake2004/dsh-security)

**DSH 生态统一安全检查框架** — 覆盖插件全生命周期（发现→安装→运行→更新→退役）。

> Community security tool. Not an official DeepSeek project.

## 定位

```
dsh-doctor          ← 执行者（运行检查）
dsh-security        ← 检查库（定义检查）
dsh-poison-guard    ← 外部集成（投毒扫描）
dsh-sandbox-audit   ← 外部集成（沙箱审计）
dsh-redact          ← 外部集成（日志脱敏）
```

## 架构

```
┌──────────────────────────────────────────────────┐
│  Layer 0: Check Protocol（统一协议）              │
│  • Severity: CRITICAL/HIGH/MEDIUM/LOW/INFO       │
│  • Phase: PRE/POST/RUNTIME/LIFECYCLE             │
│  • Plugin Interface（外部工具注册检查）            │
├──────────────────────────────────────────────────┤
│  Layer 1: Static Checks（静态检查）               │
│  • SP2: 密钥扫描（硬编码 API key/token/私钥）     │
│  • SS1: 凭据泄露检测（会话日志扫描）              │
├──────────────────────────────────────────────────┤
│  Layer 2: Runtime Checks（运行时检查）            │
│  • SR1-SR4: 即将实现                             │
├──────────────────────────────────────────────────┤
│  Layer 3: Lifecycle Checks（生命周期检查）        │
│  • SL1-SL4: 即将实现                             │
└──────────────────────────────────────────────────┘
```

## 快速开始

```javascript
import { createDefaultRegistry } from '@moonquake2004/dsh-security';

const registry = await createDefaultRegistry();
const { results, exitCode, summary } = await registry.runAll(
  (check) => profileDir  // 为每个检查提供上下文
);

console.log({ exitCode, summary });
// { exitCode: 0, summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } }
```

## 内置检查

| ID | 名称 | Severity | Phase | 描述 |
|---|---|---|---|---|
| SP2 | secret-scan | HIGH/CRITICAL | POST_INSTALL | 配置文件硬编码密钥检测 |
| SS1 | credential-leak | CRITICAL | POST_INSTALL | 会话日志凭据泄露检测 |

## 外部工具集成

通过 `~/.dsh/security/checks.d/*.json` 注册外部检查：

```json
{
  "source": "dsh-poison-guard",
  "version": "0.2.0",
  "checks": [
    {
      "id": "EXT-PG-1",
      "name": "poison-scan",
      "severity": "high",
      "phase": "pre-install",
      "command": "dsh-poison-guard scan --json"
    }
  ]
}
```

## 开发

```bash
# 运行测试
node --test test/*.mjs

# 添加新检查
# 1. 创建 src/checks/xx-check-name.mjs
# 2. 导出 runner 函数和 check 对象
# 3. 在 src/checks/index.mjs 中注册
# 4. 添加测试
```

## 设计文档

- [完整设计](docs/plans/2026-08-18-security-framework-design.md)

## License

MIT

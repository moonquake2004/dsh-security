/**
 * EXT-SA-1: dsh-sandbox-audit 集成测试（已退役）
 *
 * 决策依据见 src/integrations/sandbox-audit.mjs 头部与 docs/ecosystem-audit-2026-09.md §3(c)/§4.4：
 * 该工具从未发布到 npm（registry.npmjs.org/dsh-sandbox-audit → 404）、无 tag/release、
 * 自 2026-08-16 停更、未声明 license；真实 CLI 收 YAML 文件路径而非 profile 目录，
 * 报告形状 `{source, defaultMode, tools[], findings[{severity,title}]}` 与旧实现读取的字段不符。
 * 覆盖域由离线检查 SP3 承担，因此选择「退役」而不是重写。
 *
 * 这里锁定退役契约：恒不可用、调用即带原因的 skip、不再出现在注册表里。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isAvailable, runAudit, sandboxAuditCheck, RETIRED_REASON } from '../src/integrations/sandbox-audit.mjs';
import { getAvailableIntegrations, sandboxAuditCheck as reExported } from '../src/integrations/index.mjs';

test('EXT-SA-1: isAvailable() 恒为 false（退役后不再探测、不再注册）', () => {
  assert.equal(isAvailable(), false);
});

test('EXT-SA-1: 调用退役桩 → skip 且带退役原因，绝不 pass/fail', async () => {
  const result = await runAudit('/Users/x/.dsh/profiles/web');
  assert.equal(result.id, 'EXT-SA-1');
  assert.equal(result.skipped, true);
  assert.match(result.detail, /已退役/);
  assert.match(result.detail, /从未发布到 npm/);
  assert.match(result.detail, /SP3/);
  assert.equal(result.detail, RETIRED_REASON);
});

test('EXT-SA-1: runner 同样只返回 skip（不抛异常）', async () => {
  const result = await sandboxAuditCheck.runner('/whatever');
  assert.equal(result.skipped, true);
  assert.equal(sandboxAuditCheck.retired, true);
});

test('EXT-SA-1: 不再出现在 getAvailableIntegrations() 中', async () => {
  const integrations = await getAvailableIntegrations();
  const ids = integrations.map(c => c.id);
  assert.ok(!ids.includes('EXT-SA-1'), `退役后不应再注册 EXT-SA-1，实际：${ids.join(', ')}`);
  assert.ok(ids.includes('EXT-ECO-1'), '生态检查仍应注册');
});

test('EXT-SA-1: 兼容导出仍然存在（src/index.mjs 会 re-export 这个名字）', () => {
  assert.equal(typeof sandboxAuditCheck, 'object');
  assert.equal(reExported, sandboxAuditCheck);
});

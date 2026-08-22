/**
 * 配置系统（config.mjs + registry.setConfig）测试
 * 复审修复回归：配置此前从未接线（死代码），severityThreshold/autoRedact 未实现。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SecurityCheckRegistry } from '../src/registry.mjs';
import { loadConfig, isCheckEnabled } from '../src/config.mjs';

function dummyCheck(id, severity, ok = false) {
  return {
    id,
    name: id,
    severity,
    phase: 'post-install',
    description: `dummy ${id}`,
    src: 'builtin',
    runner: async () => ({ id, ok, severity, detail: `${id} detail` }),
  };
}

test('config: 无配置时所有检查启用', () => {
  assert.equal(isCheckEnabled(null, 'SP2'), true);
  assert.equal(isCheckEnabled(undefined, 'SR1'), true);
});

test('config: enabled=false 全局停用', () => {
  assert.equal(isCheckEnabled({ enabled: false, checks: {} }, 'SP2'), false);
});

test('config: 单检查停用', () => {
  const cfg = { enabled: true, checks: { SR1: { enabled: false } } };
  assert.equal(isCheckEnabled(cfg, 'SR1'), false);
  assert.equal(isCheckEnabled(cfg, 'SP2'), true);
});

test('registry.setConfig: 停用的检查不执行', async () => {
  const reg = new SecurityCheckRegistry();
  reg.register(dummyCheck('AAA-1', 'high'));
  reg.register(dummyCheck('BBB-2', 'low'));
  reg.setConfig({ enabled: true, checks: { 'AAA-1': { enabled: false } } });
  const { results } = await reg.runAll(() => 'ctx');
  assert.deepEqual(results.map(r => r.id), ['BBB-2']);
});

test('registry.setConfig: enabled=false 时全部停用', async () => {
  const reg = new SecurityCheckRegistry();
  reg.register(dummyCheck('CCC-1', 'high'));
  reg.setConfig({ enabled: false });
  const { results, exitCode } = await reg.runAll(() => 'ctx');
  assert.equal(results.length, 0);
  assert.equal(exitCode, 0);
});

test('registry: severityThreshold 将低于阈值的失败降级为 skipped', async () => {
  const reg = new SecurityCheckRegistry();
  reg.register(dummyCheck('LOW-F', 'low'));     // low 失败 → 低于 medium 阈值 → skipped
  reg.register(dummyCheck('HIGH-F', 'high'));   // high 失败 → 保持
  reg.setConfig({ enabled: true, checks: {}, severityThreshold: 'medium' });
  const { results, summary, exitCode } = await reg.runAll(() => 'ctx');
  const lowR = results.find(r => r.id === 'LOW-F');
  const highR = results.find(r => r.id === 'HIGH-F');
  assert.equal(lowR.skipped, true);
  assert.equal(lowR.ok, true);
  assert.ok(lowR.detail.includes('severityThreshold=medium'));
  assert.equal(highR.skipped, undefined);
  assert.equal(summary.low, 0);
  assert.equal(summary.high, 1);
  assert.equal(summary.skipped, 1);
  assert.equal(exitCode, 1); // 只有 high 计入退出码
});

test('registry: 无效 severity 的失败按 medium 计入，不静默丢失', async () => {
  const reg = new SecurityCheckRegistry();
  reg.register({
    ...dummyCheck('BAD-S', undefined),
    runner: async () => ({ id: 'BAD-S', ok: false, severity: 'wat', detail: 'x' }),
  });
  const { summary, exitCode } = await reg.runAll(() => 'ctx');
  assert.equal(summary.medium, 1);
  assert.equal(exitCode, 0); // medium → exit 0
});

test('registry.runAll: skipped 结果不计入失败统计与退出码', async () => {
  const reg = new SecurityCheckRegistry();
  reg.register({
    ...dummyCheck('SK-1', 'critical'),
    runner: async () => ({ id: 'SK-1', ok: true, skipped: true, severity: 'critical', detail: 'offline' }),
  });
  const { summary, exitCode } = await reg.runAll(() => 'ctx');
  assert.equal(summary.critical, 0);
  assert.equal(summary.skipped, 1);
  assert.equal(exitCode, 0);
});

test('config.loadConfig: 文件不存在返回默认全启用', () => {
  const cfg = loadConfig('/tmp/nonexistent-dsh-home-for-test');
  assert.equal(cfg.enabled, true);
});

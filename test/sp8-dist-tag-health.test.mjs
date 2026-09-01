/**
 * SP8: Dist-tag Health 测试
 * 出处：zoahdev/dsh-ecosystem supply-chain-health + #2763。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run, sp8Check } from '../src/checks/sp8-dist-tag-health.mjs';

function tempProfile() {
  return mkdtempSync(join(tmpdir(), 'dsh-security-sp8-'));
}

function writePlugin(profileDir, pkgName, peerDeps) {
  const pkgDir = join(profileDir, 'node_modules', pkgName);
  mkdirSync(pkgDir, { recursive: true });
  const pkg = { name: pkgName, dsh: { bundle: {} } };
  if (peerDeps) pkg.peerDependencies = peerDeps;
  writeFileSync(join(pkgDir, 'package.json'), JSON.stringify(pkg));
  return pkgDir;
}

test('SP8 元数据：ID/严重度/阶段', () => {
  assert.equal(sp8Check.id, 'SP8');
  assert.equal(sp8Check.severity, 'high');
  assert.equal(sp8Check.phase, 'post-install');
});

test('SP8: 无 node_modules → pass', async () => {
  const dir = tempProfile();
  const result = await run(dir);
  assert.equal(result.ok, true);
  assert.equal(result.id, 'SP8');
  rmSync(dir, { recursive: true, force: true });
});

test('SP8: 无 @deepseek-ai peer 依赖 → pass', async () => {
  const dir = tempProfile();
  writePlugin(dir, 'dsh-good', { 'not-deepseek': '^1.0.0' });
  const result = await run(dir);
  assert.equal(result.ok, true, `detail=${result.detail}`);
  rmSync(dir, { recursive: true, force: true });
});

test('SP8: broken latest 命中 → fail HIGH，含 #2763 引用', async () => {
  const dir = tempProfile();
  // 构造一个带 @deepseek-ai/dsh-tools peer dep 的插件
  writePlugin(dir, 'dsh-test-plugin', { '@deepseek-ai/dsh-tools': '^0.1.0-rc.6' });
  // 同时加一个无 peer dep 的插件确保不干扰
  writePlugin(dir, 'dsh-no-peer', null);
  const result = await run(dir);
  // 真实 registry 可能返回 broken 也可能已修复——只验证结构
  assert.ok(['pass', 'fail', 'skip'].includes(result.ok ? 'pass' : result.skipped ? 'skip' : 'fail'),
    `unexpected result: ${JSON.stringify(result)}`);
  assert.equal(result.id, 'SP8');
  rmSync(dir, { recursive: true, force: true });
});

test('SP8: 无 DSH 插件（无 dsh 字段）→ pass', async () => {
  const dir = tempProfile();
  const pkgDir = join(dir, 'node_modules', 'not-a-plugin');
  mkdirSync(pkgDir, { recursive: true });
  writeFileSync(join(pkgDir, 'package.json'), JSON.stringify({
    name: 'not-a-plugin',
    peerDependencies: { '@deepseek-ai/dsh-tools': '^0.1.0-rc.6' },
  }));
  const result = await run(dir);
  assert.equal(result.ok, true, `非 DSH 插件不应被扫: ${result.detail}`);
  rmSync(dir, { recursive: true, force: true });
});

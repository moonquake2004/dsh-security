/**
 * SP9: Dual-Instance Guard 测试
 * 出处：#4640 + 家族 4。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run, sp9Check } from '../src/checks/sp9-dual-instance-guard.mjs';

function tempProfile() { return mkdtempSync(join(tmpdir(), 'dsh-security-sp9-')); }

function writePkg(profileDir, scope, name, version) {
  const dir = join(profileDir, 'node_modules', scope, name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: `${scope}/${name}`, version }));
}

test('SP9 元数据：ID=SP9/严重度=critical/阶段=post-install', () => {
  assert.equal(sp9Check.id, 'SP9');
  assert.equal(sp9Check.severity, 'critical');
  assert.equal(sp9Check.phase, 'post-install');
});

test('SP9: 无 node_modules → pass', async () => {
  const dir = tempProfile();
  const r = await run(dir);
  assert.equal(r.ok, true);
  rmSync(dir, { recursive: true, force: true });
});

test('SP9: 无 @deepseek-ai 包 → pass', async () => {
  const dir = tempProfile();
  mkdirSync(join(dir, 'node_modules', 'some-pkg'), { recursive: true });
  const r = await run(dir);
  assert.equal(r.ok, true);
  rmSync(dir, { recursive: true, force: true });
});

test('SP9: 核心包 dsh-tools 泄漏 → fail CRITICAL，含 #4640', async () => {
  const dir = tempProfile();
  writePkg(dir, '@deepseek-ai', 'dsh-tools', '0.1.0-rc.6');
  const r = await run(dir);
  assert.equal(r.ok, false);
  assert.equal(r.severity, 'critical');
  assert.ok(r.detail.includes('dsh-tools'), `detail=${r.detail}`);
  assert.ok(r.references.includes('#4640'));
  rmSync(dir, { recursive: true, force: true });
});

test('SP9: 非核心包 dsh-client-ui 泄漏 → fail HIGH（非 critical）', async () => {
  const dir = tempProfile();
  writePkg(dir, '@deepseek-ai', 'dsh-client-ui-layout', '0.1.0-rc.6');
  const r = await run(dir);
  assert.equal(r.ok, false);
  assert.equal(r.severity, 'high', '非核心包应为 HIGH 而非 CRITICAL');
  assert.ok(r.detail.includes('dsh-client-ui-layout'));
  rmSync(dir, { recursive: true, force: true });
});

test('SP9: 混合泄漏（核心+非核心）→ fail CRITICAL，detail 同时提及两类', async () => {
  const dir = tempProfile();
  writePkg(dir, '@deepseek-ai', 'dsh-tools', '0.1.0-rc.6');
  writePkg(dir, '@deepseek-ai', 'dsh-client-locale', '0.1.0-rc.6');
  const r = await run(dir);
  assert.equal(r.ok, false);
  assert.equal(r.severity, 'critical');
  assert.ok(r.detail.includes('dsh-tools'));
  assert.ok(r.detail.includes('dsh-client-locale'));
  rmSync(dir, { recursive: true, force: true });
});

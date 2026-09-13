import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sp15Check, classifySpec } from '../src/checks/sp15-provenance-verifiability.mjs';

function profile(deps) {
  const dir = mkdtempSync(join(tmpdir(), 'sp15-'));
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'p', dependencies: deps }));
  return dir;
}

test('SP15 元数据：ID=SP15/严重度=medium/阶段=lifecycle', () => {
  assert.equal(sp15Check.id, 'SP15');
  assert.equal(sp15Check.severity, 'medium');
  assert.equal(sp15Check.phase, 'lifecycle');
});

test('SP15: classifySpec 分类正确', () => {
  assert.equal(classifySpec('^1.2.3').verifiable, true);
  assert.equal(classifySpec('github:user/repo').verifiable, false);
  assert.equal(classifySpec('github:user/repo#abc1234').pinned, true);
  assert.equal(classifySpec('https://x/y.tar.gz/deadbeefdeadbeefdeadbeefdeadbeefdeadbeef').pinned, true);
  assert.equal(classifySpec('file:./plugins/x').verifiable, false);
  assert.equal(classifySpec('https://x/y.tar.gz').pinned, false);
});

test('SP15: 全 registry 依赖 → pass', async () => {
  const dir = profile({ a: '^1.0.0', b: '~2.1.0' });
  const r = await sp15Check.runner(dir);
  assert.equal(r.ok, true);
  rmSync(dir, { recursive: true, force: true });
});

test('SP15: 不可核对但已内容锁定 → pass 且逐条列出', async () => {
  const dir = profile({
    a: '^1.0.0',
    'tarball-plugin': 'https://gh-proxy.com/https://codeload.github.com/u/r/tar.gz/da602d1a8f1b417b8a1d8d4059e0f4cb1c353524',
  });
  const r = await sp15Check.runner(dir);
  assert.equal(r.ok, true, '源码分发本身不是漏洞，但必须如实列出');
  assert.ok(/tarball-plugin/.test(r.detail));
  assert.ok(/不可核对来源/.test(r.detail));
  rmSync(dir, { recursive: true, force: true });
});

test('SP15: 不可核对且未锁定版本 → fail（HIGH）', async () => {
  const dir = profile({ 'loose-git': 'github:user/repo', 'loose-tar': 'https://example.com/p.tar.gz' });
  const r = await sp15Check.runner(dir);
  assert.equal(r.ok, false, '未锁定 = 上游可随时替换内容而无从察觉');
  assert.equal(r.severity, 'high');
  assert.ok(/lockfile 里也查不到 commit|未锁定/.test(r.detail), '应说明既未声明固定、lockfile 也无 commit');
  rmSync(dir, { recursive: true, force: true });
});

test('SP15: 无 package.json → skip（有理由）', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'sp15-none-'));
  const r = await sp15Check.runner(dir);
  assert.equal(r.ok, true);
  assert.equal(r.skipped, true);
  rmSync(dir, { recursive: true, force: true });
});

test('SP15（精度回归）: package.json 声明宽松但 lockfile 已固定 commit → pass，不得误报', async () => {
  const dir = profile({ 'loose-git': 'github:user/repo' });
  writeFileSync(join(dir, 'pnpm-lock.yaml'),
    '  loose-git@git+https://github.com/user/repo.git#4a281c241a5ac7511b1421714d8c9bd03daa523d:\n    resolution: {commit: 4a281c241a5ac7511b1421714d8c9bd03daa523d}\n');
  const r = await sp15Check.runner(dir);
  assert.equal(r.ok, true, 'lockfile 已固定 commit 时，内容其实是锁定的；只看 package.json 会误报成"上游可随时替换"');
  assert.ok(/lockfile 已固定/.test(r.detail));
  rmSync(dir, { recursive: true, force: true });
});

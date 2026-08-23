/**
 * SP7: Client Bundle Syntax 测试
 * 出处：deepseek-ai/deepseek-harness #2752 补充案例——client.js 语法错误 → UI 白屏。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run, sp7Check } from '../src/checks/sp7-client-syntax.mjs';

function tempProfile() {
  return mkdtempSync(join(tmpdir(), 'dsh-security-sp7-'));
}

function writePlugin(profileDir, pkgName, clientRelPath, content) {
  const pkgDir = join(profileDir, 'node_modules', pkgName);
  mkdirSync(join(pkgDir, clientRelPath, '..'), { recursive: true });
  writeFileSync(join(pkgDir, 'package.json'), JSON.stringify({ name: pkgName, dsh: { bundle: {} } }));
  if (content !== null) writeFileSync(join(pkgDir, clientRelPath), content);
  return pkgDir;
}

test('SP7 元数据：ID/严重度/阶段', () => {
  assert.equal(sp7Check.id, 'SP7');
  assert.equal(sp7Check.severity, 'high');
  assert.equal(sp7Check.phase, 'post-install');
});

test('SP7: 无 node_modules → pass 跳过', async () => {
  const dir = tempProfile();
  const result = await run(dir);
  assert.equal(result.ok, true);
  assert.equal(result.id, 'SP7');
  rmSync(dir, { recursive: true, force: true });
});

test('SP7: 正常 client.js → pass', async () => {
  const dir = tempProfile();
  writePlugin(dir, 'dsh-good', join('client', 'client.js'), '__ModuleLoader__.load({ id: "good", provide: [] });\n');
  const result = await run(dir);
  assert.equal(result.ok, true, `detail=${result.detail}`);
  assert.ok(result.detail.includes('/ 1 个 client 产物'), `detail=${result.detail}`);
  rmSync(dir, { recursive: true, force: true });
});

test('SP7 回归(#2752)：未闭合注释的 client.js → fail HIGH，含诊断行', async () => {
  const dir = tempProfile();
  writePlugin(dir, '@evil/dsh-broken', join('lib', 'client.js'), '/* unclosed comment\nconst FISH_CSS = 1;\n');
  writePlugin(dir, 'dsh-fine', join('client', 'client.js'), 'console.log("ok");\n');
  const result = await run(dir);
  assert.equal(result.ok, false, `expected fail, detail=${result.detail}`);
  assert.equal(result.severity, 'high');
  assert.ok(result.detail.includes('dsh-broken'), `detail=${result.detail}`);
  assert.ok(/SyntaxError|Unexpected/.test(result.detail), `应含语法诊断: ${result.detail}`);
  assert.ok(result.references.includes('#2752'));
  rmSync(dir, { recursive: true, force: true });
});

test('SP7: ESM 语法的 client 产物（import/export）不应误报', async () => {
  const dir = tempProfile();
  writePlugin(dir, 'dsh-esm', join('client', 'index.mjs'), 'export const boot = () => 1;\nimport { createRequire } from "node:module";\n');
  const result = await run(dir);
  assert.equal(result.ok, true, `ESM 不该被误报: ${result.detail}`);
  rmSync(dir, { recursive: true, force: true });
});

test('SP7: 无 dsh 字段的包（如普通依赖）不扫描', async () => {
  const dir = tempProfile();
  const pkgDir = join(dir, 'node_modules', 'notaplugin');
  mkdirSync(join(pkgDir, 'client'), { recursive: true });
  writeFileSync(join(pkgDir, 'package.json'), JSON.stringify({ name: 'notaplugin' }));
  writeFileSync(join(pkgDir, 'client', 'client.js'), '/* broken');
  const result = await run(dir);
  assert.equal(result.ok, true, `非插件包不应被扫: ${result.detail}`);
  assert.ok(result.detail.includes('0 个') || result.detail.includes('跳过'), `detail=${result.detail}`);
  rmSync(dir, { recursive: true, force: true });
});

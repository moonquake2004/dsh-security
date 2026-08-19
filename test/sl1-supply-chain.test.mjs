/**
 * SL1: Supply Chain Integrity 测试
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run } from '../src/checks/sl1-supply-chain.mjs';

function tempProfile(deps = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-security-sl1-'));
  mkdirSync(join(dir, 'node_modules'), { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({
    name: 'test-profile',
    dependencies: deps,
    dsh: { profile: {} },
  }));
  return dir;
}

test('SL1: no package.json → pass', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-security-sl1-empty-'));
  const result = await run(dir);
  assert.equal(result.ok, true);
  assert.equal(result.id, 'SL1');
  rmSync(dir, { recursive: true, force: true });
});

test('SL1: no dsh packages → pass', async () => {
  const dir = tempProfile({ 'lodash': '^4.17.0' });
  const result = await run(dir);
  assert.equal(result.ok, true);
  rmSync(dir, { recursive: true, force: true });
});

test('SL1: empty deps → pass', async () => {
  const dir = tempProfile({});
  const result = await run(dir);
  assert.equal(result.ok, true);
  rmSync(dir, { recursive: true, force: true });
});

test('SL1: non-existent package → skip', async () => {
  const dir = tempProfile({ 'dsh-fake-nonexistent': '1.0.0' });
  const result = await run(dir);
  // Should pass since the package doesn't exist locally
  assert.equal(result.ok, true);
  rmSync(dir, { recursive: true, force: true });
});

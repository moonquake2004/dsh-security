import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run } from '../src/checks/sl3-reputation-score.mjs';

function tempProfile(deps = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-security-sl3-'));
  mkdirSync(join(dir, 'node_modules'), { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'test', dependencies: deps }));
  return dir;
}

test('SL3: no package.json → pass', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-security-sl3-empty-'));
  const result = await run(dir);
  assert.equal(result.ok, true);
  rmSync(dir, { recursive: true, force: true });
});

test('SL3: no dsh packages → pass', async () => {
  const dir = tempProfile({ lodash: '^4.0.0' });
  const result = await run(dir);
  assert.equal(result.ok, true);
  rmSync(dir, { recursive: true, force: true });
});

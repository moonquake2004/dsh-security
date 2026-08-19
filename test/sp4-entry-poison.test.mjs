import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run } from '../src/checks/sp4-entry-poison.mjs';

function tempProfile(patchContent = '') {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-security-sp4-'));
  mkdirSync(join(dir, 'node_modules'), { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'test' }));
  if (patchContent) writeFileSync(join(dir, 'cordis.patch.yml'), patchContent);
  return dir;
}

test('SP4: clean patch → pass', async () => {
  const dir = tempProfile('- id: test\n  name: safe-module\n');
  const result = await run(dir);
  assert.equal(result.ok, true);
  rmSync(dir, { recursive: true, force: true });
});

test('SP4: eval in patch → fail', async () => {
  const dir = tempProfile('code: "eval(malicious)"\n');
  const result = await run(dir);
  assert.equal(result.ok, false);
  rmSync(dir, { recursive: true, force: true });
});

test('SP4: no patch files → pass', async () => {
  const dir = tempProfile();
  const result = await run(dir);
  assert.equal(result.ok, true);
  rmSync(dir, { recursive: true, force: true });
});

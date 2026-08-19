/**
 * SP3: Sandbox Consistency 测试
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run } from '../src/checks/sp3-sandbox-consistency.mjs';

function tempProfile() {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-security-sp3-'));
  mkdirSync(join(dir, 'node_modules'), { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'test-profile' }));
  return dir;
}

test('SP3: no patch files → pass', async () => {
  const dir = tempProfile();
  const result = await run(dir);
  assert.equal(result.ok, true);
  rmSync(dir, { recursive: true, force: true });
});

test('SP3: safe sandbox-policy → pass', async () => {
  const dir = tempProfile();
  writeFileSync(join(dir, 'cordis.patch.yml'), `- insert:
    - id: sandbox-policy
      config:
        mode: workspace-write
`);
  const result = await run(dir);
  assert.equal(result.ok, true);
  rmSync(dir, { recursive: true, force: true });
});

test('SP3: danger-full-access (non-Windows) → fail', async () => {
  const dir = tempProfile();
  writeFileSync(join(dir, 'cordis.patch.yml'), `- insert:
    - id: sandbox-policy
      config:
        mode: danger-full-access
`);
  const result = await run(dir);
  assert.equal(result.ok, false);
  assert.equal(result.severity, 'medium');
  assert.ok(result.detail.includes('danger-full-access'));
  rmSync(dir, { recursive: true, force: true });
});

test('SP3: tool-fs without sandbox config → fail', async () => {
  const dir = tempProfile();
  writeFileSync(join(dir, 'cordis.patch.yml'), `- insert:
    - id: tool-fs
      name: some-module
`);
  const result = await run(dir);
  assert.equal(result.ok, false);
  assert.ok(result.detail.includes('tool-fs'));
  rmSync(dir, { recursive: true, force: true });
});

test('SP3: tool-fs with sandbox config → pass', async () => {
  const dir = tempProfile();
  writeFileSync(join(dir, 'cordis.patch.yml'), `- insert:
    - id: tool-fs
      name: some-module
      config:
        sandbox: workspace-write
`);
  const result = await run(dir);
  // tool-fs has sandbox config, should pass
  assert.equal(result.ok, true);
  rmSync(dir, { recursive: true, force: true });
});

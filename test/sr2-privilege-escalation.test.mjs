import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run } from '../src/checks/sr2-privilege-escalation.mjs';

function tempSession(lines) {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-security-sr2-'));
  const file = join(dir, 'session.jsonl');
  writeFileSync(file, lines.join('\n'));
  return file;
}

test('SR2: clean session → pass', async () => {
  const file = tempSession([JSON.stringify({ type: 'tool/call', data: { name: 'tool-fs', args: { path: '/workspace/test.txt' } } })]);
  const result = await run(file);
  assert.equal(result.ok, true);
  rmSync(join(file, '..'), { recursive: true, force: true });
});

test('SR2: sudo usage → fail', async () => {
  const file = tempSession([JSON.stringify({ type: 'tool/call', data: { name: 'tool-bash', args: { command: 'sudo apt install' } } })]);
  const result = await run(file);
  assert.equal(result.ok, false);
  assert.ok(result.detail.includes('sudo'));
  rmSync(join(file, '..'), { recursive: true, force: true });
});

test('SR2: non-existent file → pass', async () => {
  const result = await run('/tmp/nonexistent.jsonl');
  assert.equal(result.ok, true);
});

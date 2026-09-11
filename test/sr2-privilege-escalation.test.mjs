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

test('SR2: 裸 sudo 属常见操作 → 不计为提权发现（2026-09 语义收窄）', async () => {
  const file = tempSession([JSON.stringify({ type: 'tool/call', seq: 1, data: { turn: 1, step: 1, callId: 'c1', name: 'bash', arguments: JSON.stringify({ command: 'sudo apt install' }) } })]);
  const result = await run(file);
  assert.equal(result.ok, true, '裸 sudo 在日常操作里极常见，不构成提权判定');
  rmSync(join(file, '..'), { recursive: true, force: true });
});

test('SR2: sudo -i / chmod u+s 等原语 → fail（真实形态）', async () => {
  const file = tempSession([
    JSON.stringify({ type: 'tool/call', seq: 1, data: { turn: 1, step: 1, callId: 'c2', name: 'bash', arguments: JSON.stringify({ command: 'sudo -i' }) } }),
    JSON.stringify({ type: 'tool/call', seq: 2, data: { turn: 1, step: 1, callId: 'c3', name: 'bash', arguments: JSON.stringify({ command: 'chmod u+s /tmp/x' }) } }),
  ]);
  const result = await run(file);
  assert.equal(result.ok, false, '提权原语必须检出');
  assert.ok(/root shell|setuid/i.test(result.detail));
  rmSync(join(file, '..'), { recursive: true, force: true });
});

test('SR2: non-existent file → pass', async () => {
  const result = await run('/tmp/nonexistent.jsonl');
  assert.equal(result.ok, true);
});

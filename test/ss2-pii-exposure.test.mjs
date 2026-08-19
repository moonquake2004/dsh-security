import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run } from '../src/checks/ss2-pii-exposure.mjs';

function tempSession(lines) {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-security-ss2-'));
  const file = join(dir, 'session.jsonl');
  writeFileSync(file, lines.join('\n'));
  return file;
}

test('SS2: clean session → pass', async () => {
  const file = tempSession([JSON.stringify({ type: 'user/message', data: { message: { content: [{ type: 'text', text: 'hello' }] } } })]);
  const result = await run(file);
  assert.equal(result.ok, true);
  rmSync(join(file, '..'), { recursive: true, force: true });
});

test('SS2: email in session → fail', async () => {
  const file = tempSession([JSON.stringify({ type: 'user/message', data: { message: { content: [{ type: 'text', text: 'my email is test@example.com' }] } } })]);
  const result = await run(file);
  assert.equal(result.ok, false);
  assert.ok(result.detail.includes('email'));
  rmSync(join(file, '..'), { recursive: true, force: true });
});

test('SS2: non-existent file → pass', async () => {
  const result = await run('/tmp/nonexistent.jsonl');
  assert.equal(result.ok, true);
});

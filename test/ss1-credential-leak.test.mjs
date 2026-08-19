/**
 * SS1: Credential Leak 测试
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run } from '../src/checks/ss1-credential-leak.mjs';

function tempSession(lines) {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-security-ss1-'));
  const file = join(dir, 'session.jsonl');
  writeFileSync(file, lines.join('\n'));
  return file;
}

test('SS1: clean session → pass', async () => {
  const file = tempSession([
    JSON.stringify({ type: 'user/message', data: { message: { content: [{ type: 'text', text: 'hello' }] } } }),
    JSON.stringify({ type: 'assistant/message', data: { message: { content: [{ type: 'text', text: 'hi there' }] } } }),
  ]);
  const result = await run(file);
  assert.equal(result.ok, true);
  assert.equal(result.id, 'SS1');
  rmSync(join(file, '..'), { recursive: true, force: true });
});

test('SS1: session with API key → fail', async () => {
  const file = tempSession([
    JSON.stringify({ type: 'user/message', data: { message: { content: [{ type: 'text', text: 'my key is sk-1234567890abcdef1234567890abcdef' }] } } }),
  ]);
  const result = await run(file);
  assert.equal(result.ok, false);
  assert.equal(result.severity, 'critical');
  assert.ok(result.detail.includes('OpenAI API Key'));
  rmSync(join(file, '..'), { recursive: true, force: true });
});

test('SS1: session with GitHub PAT → fail', async () => {
  const file = tempSession([
    JSON.stringify({ type: 'user/message', data: { message: { content: [{ type: 'text', text: 'token: ghp_abcdef1234567890abcdef1234567890abcdef' }] } } }),
  ]);
  const result = await run(file);
  assert.equal(result.ok, false);
  assert.ok(result.detail.includes('GitHub PAT'));
  rmSync(join(file, '..'), { recursive: true, force: true });
});

test('SS1: non-existent file → pass (skip)', async () => {
  const result = await run('/tmp/nonexistent-session.jsonl');
  assert.equal(result.ok, true);
});

test('SS1: zstd file → pass (skip, needs decompress)', async () => {
  const result = await run('/tmp/fake-session.jsonl.zstd');
  assert.equal(result.ok, true);
});

test('SS1: empty session → pass', async () => {
  const file = tempSession(['']);
  const result = await run(file);
  assert.equal(result.ok, true);
  rmSync(join(file, '..'), { recursive: true, force: true });
});

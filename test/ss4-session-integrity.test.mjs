/**
 * SS4: Session Integrity 测试
 * 出处：家族 3/11。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run, ss4Check } from '../src/checks/ss4-session-integrity.mjs';

function tmp() { return mkdtempSync(join(tmpdir(), 'dsh-security-ss4-')); }

test('SS4 元数据：ID=SS4/严重度=high/阶段=post-install', () => {
  assert.equal(ss4Check.id, 'SS4');
  assert.equal(ss4Check.severity, 'high');
  assert.equal(ss4Check.phase, 'post-install');
});

test('SS4: 无文件 → skip', async () => {
  const r = await run(null);
  assert.equal(r.ok, true);
  assert.equal(r.skipped, true);
});

test('SS4: 空文件 → fail', async () => {
  const dir = tmp();
  const f = join(dir, 'session.jsonl');
  writeFileSync(f, '');
  const r = await run(f);
  assert.equal(r.ok, false);
  assert.ok(r.detail.includes('空'));
  rmSync(dir, { recursive: true, force: true });
});

test('SS4: 正常会话 → pass', async () => {
  const dir = tmp();
  const f = join(dir, 'session.jsonl');
  const lines = [];
  for (let i = 0; i < 15; i++) {
    lines.push(JSON.stringify({ type: 'assistant/message', seq: i, data: {} }));
  }
  // 加一组 tool/call + tool/result 配对
  lines.push(JSON.stringify({ type: 'tool/call', seq: 100, data: { callId: 'abc123' } }));
  lines.push(JSON.stringify({ type: 'tool/result', seq: 101, data: { callId: 'abc123' } }));
  writeFileSync(f, lines.join('\n'));
  const r = await run(f);
  assert.equal(r.ok, true, `detail=${r.detail}`);
  rmSync(dir, { recursive: true, force: true });
});

test('SS4: 孤儿 tool/call → fail，含 #3234', async () => {
  const dir = tmp();
  const f = join(dir, 'session.jsonl');
  const lines = [];
  for (let i = 0; i < 12; i++) lines.push(JSON.stringify({ type: 'msg', seq: i }));
  lines.push(JSON.stringify({ type: 'tool/call', seq: 100, data: { callId: 'orphan1' } }));
  // 无对应 tool/result
  writeFileSync(f, lines.join('\n'));
  const r = await run(f);
  assert.equal(r.ok, false);
  assert.ok(r.detail.includes('孤儿'), `detail=${r.detail}`);
  assert.ok(r.references.includes('#3234'));
  rmSync(dir, { recursive: true, force: true });
});

test('SS4: 无效 JSON 行 → fail，含 #675', async () => {
  const dir = tmp();
  const f = join(dir, 'session.jsonl');
  const lines = [];
  for (let i = 0; i < 12; i++) lines.push(JSON.stringify({ type: 'msg', seq: i }));
  lines[5] = '{"truncated json...'; // 无效 JSON
  writeFileSync(f, lines.join('\n'));
  const r = await run(f);
  assert.equal(r.ok, false);
  assert.ok(r.detail.includes('无效 JSON'), `detail=${r.detail}`);
  assert.ok(r.references.includes('#675'));
  rmSync(dir, { recursive: true, force: true });
});

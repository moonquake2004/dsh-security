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
  // 真实 v3 形态：turn 1 的调用没有结果（真孤儿）；后面还有 turn 2，故 turn 1 已闭合
  lines.push(JSON.stringify({ type: 'tool/call', seq: 100, data: { turn: 1, step: 1, callId: 'orphan1', name: 'bash', arguments: '{"command":"ls"}' } }));
  lines.push(JSON.stringify({ type: 'user/message', seq: 101, data: { turn: 2, step: 0, message: { content: [] } } }));
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

test('SS4: 仅尾部 turn 有未配对调用 → pass（in-flight 豁免，2026-09 修复）', async () => {
  const dir = tmp();
  const f = join(dir, 'session.jsonl');
  const lines = [];
  for (let i = 0; i < 12; i++) lines.push(JSON.stringify({ type: 'msg', seq: i }));
  // 只出现在最后一个 turn：正在执行，属正常
  lines.push(JSON.stringify({ type: 'tool/call', seq: 100, data: { turn: 3, step: 1, callId: 'inflight1', name: 'bash', arguments: '{"command":"sleep 1"}' } }));
  writeFileSync(f, lines.join('\n'));
  const r = await run(f);
  assert.equal(r.ok, true, '尾部 in-flight 不得报为孤儿（旧实现会误报）');
  rmSync(dir, { recursive: true, force: true });
});

test('SS4: v3 真实形态的 result（callId 在 data.message.source）能正确配对', async () => {
  const dir = tmp();
  const f = join(dir, 'session.jsonl');
  const lines = [];
  for (let i = 0; i < 12; i++) lines.push(JSON.stringify({ type: 'msg', seq: i }));
  lines.push(JSON.stringify({ type: 'tool/call', seq: 100, data: { turn: 1, step: 1, callId: 'c1', name: 'bash', arguments: '{"command":"pwd"}' } }));
  lines.push(JSON.stringify({ type: 'tool/result', seq: 101, data: { turn: 1, step: 1, message: { source: { kind: 'tool', callId: 'c1' }, content: [{ type: 'tool-result', toolCallId: 'c1', content: [{ type: 'text', text: '/tmp' }] }] } } }));
  lines.push(JSON.stringify({ type: 'user/message', seq: 102, data: { turn: 2, step: 0, message: { content: [] } } }));
  writeFileSync(f, lines.join('\n'));
  const r = await run(f);
  assert.equal(r.ok, true, 'v3 的 result 必须能与 call 配对（旧实现读 data.callId → 永远配不上）');
  rmSync(dir, { recursive: true, force: true });
});

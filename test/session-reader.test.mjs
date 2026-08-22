/**
 * session-reader（zstd 支持）回归测试
 * 复审修复：SR/SS 系列此前对 .zstd 一律跳过，运行时层在真实部署（zstd 日志）下永不工作。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { scanSessionLines } from '../src/session-reader.mjs';

let hasZstd = true;
try {
  execFileSync('which', ['zstd'], { stdio: 'pipe' });
} catch {
  hasZstd = false;
}

test('scanSessionLines: 明文 jsonl 逐行读取', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-security-sr-plain-'));
  const file = join(dir, 'session.jsonl');
  writeFileSync(file, '{"a":1}\n{"a":2}\n\n{"a":3}\n');
  const seen = [];
  const n = await scanSessionLines(file, (line) => seen.push(line));
  assert.equal(n, 4); // 含空行
  assert.deepEqual(seen.filter(Boolean).map(s => JSON.parse(s).a), [1, 2, 3]);
  rmSync(dir, { recursive: true, force: true });
});

if (hasZstd) {
  test('scanSessionLines: zstd 压缩会话自动解压读取', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-security-sr-zstd-'));
    const plain = join(dir, 'session.jsonl');
    const packed = join(dir, 'session.jsonl.zstd');
    writeFileSync(plain, '{"type":"tool/call","data":{"name":"bash","args":{"command":"sudo ls"}}}\n{"type":"other"}\n');
    execFileSync('zstd', ['-f', '-q', plain, '-o', packed]);
    const seen = [];
    const n = await scanSessionLines(packed, (line) => seen.push(line));
    assert.equal(n, 2);
    assert.ok(seen[0].includes('sudo'));
    rmSync(dir, { recursive: true, force: true });
  });

  test('scanSessionLines: 损坏的 zstd 文件应抛错而不是静默当空文件', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'dsh-security-sr-bad-'));
    const bad = join(dir, 'session.jsonl.zstd');
    writeFileSync(bad, 'this is not zstd data\n');
    await assert.rejects(() => scanSessionLines(bad, () => {}));
    rmSync(dir, { recursive: true, force: true });
  });
} else {
  test('zstd 不可用：跳过压缩相关用例（本机未安装 zstd）', () => {
    assert.equal(hasZstd, false);
  });
}

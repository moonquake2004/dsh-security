/**
 * DSH Security Framework — 会话日志读取
 *
 * SR/SS 系列检查共用：透明支持明文 .jsonl 与 zstd 压缩的 session.jsonl.zstd
 * （真实 DSH 部署中会话日志为 ~/.dsh/sessions/<user>/<session>/session.jsonl.zstd）。
 *
 * 依赖系统 zstd 命令解压（macOS: brew install zstd；Debian: apt install zstd）。
 * 二进制不可用时抛 code='ZSTD_UNAVAILABLE'，检查应转为 skip 而非误报通过。
 */

import { createReadStream } from 'node:fs';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';

export function isZstdFile(sessionFile) {
  return typeof sessionFile === 'string' && (sessionFile.endsWith('.zstd') || sessionFile.endsWith('.zst'));
}

function openStream(sessionFile) {
  if (isZstdFile(sessionFile)) {
    const child = spawn('zstd', ['-dc', sessionFile], { stdio: ['ignore', 'pipe', 'pipe'] });
    let stderrTail = '';
    let spawnErr = null;
    child.stderr.on('data', (d) => { stderrTail += String(d); });
    const settled = new Promise((resolve) => {
      child.once('error', (e) => { spawnErr = e; resolve(); });
      child.once('close', () => resolve());
    });
    return { stream: child.stdout, settled, getErr: () => (spawnErr ? spawnErr : stderrTail.trim() || null) };
  }
  return { stream: createReadStream(sessionFile, { encoding: 'utf8' }), settled: Promise.resolve(), getErr: () => null };
}

/**
 * 逐行扫描会话文件（自动解压 zstd）。
 * @param {string} sessionFile 会话文件路径
 * @param {(line: string, lineNo: number) => void|Promise<void>} onLine 每行回调
 * @returns {Promise<number>} 实际读取的总行数
 */
export async function scanSessionLines(sessionFile, onLine) {
  const { stream, settled, getErr } = openStream(sessionFile);
  const rl = createInterface({ input: stream, crlfDelay: Infinity });
  let lineCount = 0;
  try {
    for await (const line of rl) {
      lineCount++;
      await onLine(line, lineCount);
    }
  } finally {
    await settled.catch(() => {});
    if (typeof stream.destroy === 'function') stream.destroy();
  }
  const err = getErr();
  if (err) {
    if (err.code === 'ENOENT') {
      const e = new Error('zstd 命令不可用（PATH 中未找到），无法解压压缩会话日志');
      e.code = 'ZSTD_UNAVAILABLE';
      throw e;
    }
    throw new Error(`会话日志读取失败：${String(err).split('\n').pop().slice(0, 100)}`);
  }
  return lineCount;
}

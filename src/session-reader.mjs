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

/* ================= 世代感知的会话定位 + 归一化载荷（形态规范见 docs/session-shape-v3.md） =================
 * 2026-09 回归教训：DSH 起用 session.v<N>.jsonl.zstd（当前 v3），旧定位器只认 session.jsonl[.zstd]，
 * 导致整套 SR/SS 检查在分析 2 天前的旧世代日志。此后定位必须世代感知。
 */

import { existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

/** 会话文件名：session.jsonl[.zstd] / session.v<N>.jsonl[.zstd]（无 .vN 视为世代 0）。 */
export const SESSION_FILE_RE = /^session(?:\.v(\d+))?\.jsonl(\.zstd|\.zst)?$/;

/** 从文件名解析世代号；非会话文件返回 -1。 */
export function sessionGeneration(fileName) {
  const m = SESSION_FILE_RE.exec(fileName);
  return m ? Number(m[1] ?? 0) : -1;
}

/** 同一会话目录内取最高世代的日志文件（.zstd 优先）；无匹配返回 null。 */
function bestLogInDir(dir) {
  let entries;
  try { entries = readdirSync(dir); } catch { return null; }
  let best = null;
  for (const name of entries) {
    const gen = sessionGeneration(name);
    if (gen < 0) continue;
    const f = join(dir, name);
    let st;
    try { st = statSync(f); } catch { continue; }
    if (!st.isFile()) continue;
    const isZstd = /\.zst(d)?$/.test(name) ? 1 : 0;
    if (!best || gen > best.generation || (gen === best.generation && isZstd > best.isZstd)) {
      best = { file: f, generation: gen, isZstd, mtimeMs: st.mtimeMs };
    }
  }
  return best;
}

/**
 * 定位最新会话日志（世代感知）。
 * - 同一会话目录：取最高世代（而非文件名字典序）
 * - 跨目录：按 mtime 取最新
 * - 忽略 session.lock；兼容散落在 user 目录下的 session.jsonl
 * @param {string} dshHome DSH home（含 sessions/）
 * @returns {{file: string, generation: number, mtimeMs: number}|null}
 */
export function findLatestSession(dshHome) {
  const root = join(dshHome, 'sessions');
  if (!existsSync(root)) return null;
  let best = null;
  let projects;
  try { projects = readdirSync(root); } catch { return null; }
  for (const proj of projects) {
    if (proj === 'session.lock') continue;
    const pdir = join(root, proj);
    let subs;
    try { subs = readdirSync(pdir, { withFileTypes: true }); } catch { continue; }
    for (const sub of subs) {
      if (!sub.isDirectory()) {
        // 散文件：sessions/<proj>/session*.jsonl*
        if (sub.isFile() && sessionGeneration(sub.name) >= 0) {
          const f = join(pdir, sub.name);
          let st; try { st = statSync(f); } catch { continue; }
          if (!best || st.mtimeMs > best.mtimeMs) best = { file: f, generation: sessionGeneration(sub.name), mtimeMs: st.mtimeMs };
        }
        continue;
      }
      const cand = bestLogInDir(join(pdir, sub.name));
      if (cand && (!best || cand.mtimeMs > best.mtimeMs)) best = cand;
    }
  }
  return best;
}

/**
 * 归一化事件载荷 —— SR/SS 检查**只应从这里取字段**，不要各自猜字段名。
 * 兼容 v3（data.arguments 为 JSON 字符串、结果嵌在 data.message）与旧世代（扁平 args/input/output/result/text）。
 * @returns {{kind:'call'|'result'|'other', type:string, name:string|null, argsText:string,
 *            callId:string|null, resultText:string, turn:number|null, step:number|null, seq:number|null}}
 */
export function extractEvent(event) {
  const data = (event && typeof event.data === 'object' && event.data) || {};
  const type = String(event?.type ?? '');
  const kind = type === 'tool/call' ? 'call' : type === 'tool/result' ? 'result' : 'other';

  let argsText = '';
  const rawArgs = data.arguments ?? data.args ?? data.input;
  if (typeof rawArgs === 'string') argsText = rawArgs;
  else if (rawArgs != null) { try { argsText = JSON.stringify(rawArgs); } catch { argsText = String(rawArgs); } }

  const msg = (typeof data.message === 'object' && data.message) || null;
  const blocks = msg && Array.isArray(msg.content) ? msg.content : [];
  const callId = data.callId
    ?? msg?.source?.callId
    ?? blocks.find((b) => b && typeof b.toolCallId === 'string')?.toolCallId
    ?? null;

  const parts = [];
  for (const blk of blocks) {
    if (!blk || typeof blk !== 'object') continue;
    if (Array.isArray(blk.content)) {
      for (const inner of blk.content) if (inner && typeof inner.text === 'string') parts.push(inner.text);
    } else if (typeof blk.text === 'string') parts.push(blk.text);
    if (typeof blk.output === 'string') parts.push(blk.output);
  }
  let resultText = parts.join('\n');
  if (!resultText) {
    const flat = data.output ?? data.result ?? data.text;
    if (typeof flat === 'string') resultText = flat;
    else if (flat != null) { try { resultText = JSON.stringify(flat); } catch { /* 忽略 */ } }
  }

  const turn = typeof data.turn === 'number' ? data.turn : (typeof event?.turn === 'number' ? event.turn : null);
  const step = typeof data.step === 'number' ? data.step : (typeof event?.step === 'number' ? event.step : null);
  return { kind, type, name: data.name ?? data.tool ?? null, argsText, callId, resultText, turn, step, seq: typeof event?.seq === 'number' ? event.seq : null };
}

/**
 * 是否"命令执行类"工具 —— 静态沙箱/提权/外泄规则只应作用于这类工具。
 * 否则文档工具（write/edit）里**引用**路径（如审计文档里写 `/etc/passwd`）会被误判为逃逸行为
 * （2026-09 实测：解除失明后 SR1 在真实日志上报 361 处，绝大多数是这种"提到而非执行"）。
 * 判定：工具名像 shell，或参数 JSON 顶层含 command/script/cmd。
 */
export function isShellTool(name, argsText) {
  if (typeof name === 'string' && /(^|[^a-z])(bash|sh|shell|zsh|exec|terminal|command|run|script|process)/i.test(name)) return true;
  if (typeof argsText === 'string' && argsText) {
    try {
      const o = JSON.parse(argsText);
      if (o && typeof o === 'object' && !Array.isArray(o)
          && (typeof o.command === 'string' || typeof o.script === 'string' || typeof o.cmd === 'string')) return true;
    } catch { /* 非 JSON 参数：按非 shell 处理 */ }
  }
  return false;
}

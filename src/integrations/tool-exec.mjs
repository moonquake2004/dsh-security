/**
 * 外部工具调用助手（跨平台）——供 EXT-* 集成共用
 *
 * 复审修复（docs/ecosystem-audit-2026-09.md §3(c)/§4.4），两处共性问题：
 *
 * 1. `which` 探测不可移植：Windows 没有 `which`，旧实现的 `isAvailable()` 在 Windows 上
 *    永远返回 false（连带把「工具未安装」和「平台不支持」混为一谈）。
 *    这里改为纯 Node 的 PATH 扫描：POSIX 校验可执行位，Windows 额外按 PATHEXT 匹配
 *    .COM/.EXE/.BAT/.CMD。不启动任何子进程，因此探测本身不会执行第三方代码。
 *
 * 2. `execFileSync` 会把「非零退出码」变成异常：poison-guard 用 exit 1 表示「发现投毒」、
 *    reducer 用 exit 1 表示「归约失败并给出了 error envelope」，两者在非零退出时**都仍然
 *    往 stdout 写结构化 JSON**。用 execFileSync 时这些 stdout 随异常一起丢掉，
 *    真实发现退化成一句没有信息的 skip。
 *    这里改用 `spawnSync` 包装，永不抛异常，把 stdout/stderr/退出码/signal 一并交回调用方判断。
 */

import { spawnSync } from 'node:child_process';
import { accessSync, constants, statSync } from 'node:fs';
import { delimiter, extname, isAbsolute, join } from 'node:path';

const WINDOWS = process.platform === 'win32';

/** 默认的 Windows 可执行扩展名（PATH 中没有 PATHEXT 时的回退） */
const DEFAULT_PATHEXT = '.COM;.EXE;.BAT;.CMD';

/**
 * 在 PATH 中查找可执行文件，返回绝对路径；找不到返回 null。
 * 纯 fs 扫描，不 fork 子进程——探测第三方工具可用性时不应执行第三方代码。
 *
 * @param {string} bin 可执行文件名（也可传含路径分隔符的相对/绝对路径）
 * @param {NodeJS.ProcessEnv} [env]
 * @returns {string|null}
 */
export function findExecutable(bin, env = process.env) {
  if (!bin || typeof bin !== 'string') return null;

  const explicitPath = isAbsolute(bin) || bin.includes('/') || bin.includes('\\');
  const dirs = explicitPath
    ? ['']
    : String(env.PATH ?? env.Path ?? '').split(delimiter).filter(Boolean);

  const exts = WINDOWS
    ? String(env.PATHEXT ?? DEFAULT_PATHEXT).split(';').map(e => e.trim()).filter(Boolean)
    : [''];

  for (const dir of dirs) {
    const base = dir ? join(dir, bin) : bin;
    const candidates = [base];
    // 已带扩展名（如 dsh-plugin-reducer.cmd）时不再叠加 PATHEXT
    if (WINDOWS && !extname(base)) {
      for (const ext of exts) candidates.push(base + ext.toLowerCase(), base + ext.toUpperCase());
    }
    for (const candidate of candidates) {
      try {
        if (!statSync(candidate).isFile()) continue;
        // POSIX：必须是可执行文件；Windows：X_OK 无实义，但 accessSync 仍可用于存在性确认
        if (!WINDOWS) accessSync(candidate, constants.X_OK);
        return candidate;
      } catch { /* 试下一个候选 */ }
    }
  }
  return null;
}

/**
 * 执行外部命令并返回结构化结果——**永不抛异常**。
 *
 * @param {string} bin
 * @param {string[]} args
 * @param {{timeoutMs?: number, env?: object, cwd?: string, maxBuffer?: number}} [options]
 * @returns {{status: number|null, signal: string|null, stdout: string, stderr: string, error: Error|null}}
 */
export function execCapture(bin, args, options = {}) {
  const { timeoutMs = 60000, env, cwd, maxBuffer = 16 * 1024 * 1024 } = options;
  const result = spawnSync(bin, args, {
    encoding: 'utf8',
    timeout: timeoutMs,
    maxBuffer,
    stdio: ['ignore', 'pipe', 'pipe'],
    ...(env ? { env } : {}),
    ...(cwd ? { cwd } : {}),
    // Windows 上 npm 安装的可执行文件是 .cmd/.bat 垫片，不经过 shell 无法直接 spawn
    shell: WINDOWS,
  });

  return {
    status: result.status ?? null,
    signal: result.signal ?? null,
    stdout: typeof result.stdout === 'string' ? result.stdout : '',
    stderr: typeof result.stderr === 'string' ? result.stderr : '',
    error: result.error ?? null,
  };
}

/**
 * 把一次失败执行压缩成一行可读原因（用于 skip 的 reason）。
 * @param {{status: number|null, signal: string|null, stderr: string, error: Error|null}} res
 */
export function describeFailure(res) {
  const bits = [];
  if (res?.error?.message) bits.push(String(res.error.message).slice(0, 120));
  if (res?.signal) bits.push(`signal=${res.signal}`);
  bits.push(`exit=${res?.status ?? 'null'}`);
  const lastStderrLine = String(res?.stderr ?? '').trim().split('\n').filter(Boolean).pop();
  if (lastStderrLine) bits.push(lastStderrLine.slice(0, 120));
  return bits.join(', ');
}

/**
 * 解析 stdout 上的 JSON，返回 {ok, value}；不抛异常。
 * 工具约定「一行 JSON envelope」或任意 JSON 文档，这里整段解析。
 * @param {string} text
 */
export function parseJson(text) {
  const trimmed = String(text ?? '').trim();
  if (trimmed === '') return { ok: false, value: undefined };
  try {
    return { ok: true, value: JSON.parse(trimmed) };
  } catch {
    return { ok: false, value: undefined };
  }
}

/** JS 值的类型名，用于「契约已变化」类 skip 的原因描述 */
export function typeName(value) {
  if (value === null) return 'null';
  if (Array.isArray(value)) return 'array';
  return typeof value;
}

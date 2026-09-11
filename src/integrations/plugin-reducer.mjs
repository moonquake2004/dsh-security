/**
 * dsh-plugin-reducer 集成
 *
 * 在检测到故障时，提供最小化故障插件集的能力。
 * 如果 dsh-plugin-reducer 已安装（PATH 中可执行），自动集成到安全检查流程。
 * 复审修复：不再用 `npx 包名` 探测/执行；执行失败返回 skip 而不是伪装通过。
 *
 * 复审修复（docs/ecosystem-audit-2026-09.md §3(c) EXT-RED-1 / §4.4）——**调用方式与结果路径都不对**：
 *
 * 1. `--profile` 收的是 profile **名**，不是路径（上游 `src/args.js` HELP：`--profile <name> (default: web)`、
 *    `--dsh-home <path> Source DSH_HOME`）。旧代码传的是 profile 目录的绝对路径，
 *    工具会把整条路径当成 profile 名 → 归约不了任何东西。现在从 registry 交付的 profile 目录
 *    （`<dshHome>/profiles/<name>`）反推名字与 dsh home，两个参数分别传。
 *
 * 2. 结果路径。机器契约是 stdout 上**一个** envelope：
 *      `{ schemaVersion, tool: {name, version}, operation, ok, report | candidates | error }`
 *    （上游 `src/machine-output.js`），答案在 `report.result.minimalFailingSet`
 *    （上游 `src/index.js`：`result: { status: 'minimal-failure-set-found', minimalFailingSet: reduced.minimal, … }`）。
 *    旧代码读 `result.minimalSet` —— 永远 undefined，于是**找到故障集也判为通过**。
 *
 * 3. 便携性。旧代码把 `--report` 硬编码到 `/tmp`（Windows 无此路径）并用 `which` 探测
 *    （Windows 无此命令 → 永久「未安装」）。现在 `--report` 落在 `os.tmpdir()` 下的一次性目录并在
 *    finally 中清理；探测改用 tool-exec.mjs 的 PATH 扫描。
 *
 * 4. 语义收紧：`ok:true` 只可能出现在「确实归约出了最小故障集」的路径上
 *    （上游 index.js 在 FULL_SET_PASSES / BASELINE_FAILS / FINAL_NOT_REPRODUCIBLE 等情况下抛 ReducerError
 *     → envelope `ok:false` + `error.code` + exit 1）。因此 `ok:true` 但 `minimalFailingSet` 缺失/为空
 *    属于契约矛盾 → 显式 skip，绝不判 pass。
 */

import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { skip, fail } from '../protocol/check.mjs';
import { findExecutable, execCapture, parseJson, describeFailure, typeName } from './tool-exec.mjs';

export const REDUCER_ID = 'EXT-RED-1';
const BIN = 'dsh-plugin-reducer';
const SUPPORTED_SCHEMA_VERSION = 1;
const PROBE_KINDS = new Set(['config', 'web', 'command']);
/** 沿用旧实现的默认探针；工具自身的默认是 config（见 src/args.js HELP） */
const DEFAULT_PROBE = 'web';

/**
 * 检测 dsh-plugin-reducer 是否可用（跨平台 PATH 扫描，不启动子进程）
 */
export function isAvailable() {
  return findExecutable(BIN) !== null;
}

/**
 * 从 profile 目录反推工具需要的 `{ dshHome, profile }`。
 *
 * registry 交给 EXT-* 的是 profile 目录（如 `~/.dsh/profiles/web`），而 CLI 要的是
 * `--dsh-home <path> --profile <name>`。规则：
 *   `<home>/profiles/<name>` → { dshHome: '<home>', profile: '<name>' }
 *   纯名字（不含路径分隔符，如 `web`）→ { dshHome: null, profile: 'web' }（由工具走 DSH_HOME/~/.dsh）
 *   其它任意目录 → null（无法安全推断，调用方应 skip）
 *
 * @param {string} profileDir
 * @returns {{dshHome: string|null, profile: string}|null}
 */
export function deriveProfileArgs(profileDir) {
  if (!profileDir || typeof profileDir !== 'string') return null;
  const normalized = profileDir.replace(/\\/g, '/').replace(/\/+$/, '');
  if (normalized === '') return null;

  const matched = normalized.match(/^(.*)\/profiles\/([^/]+)$/);
  if (matched) {
    const [, home, name] = matched;
    return { dshHome: home || null, profile: name };
  }
  // 不含路径分隔符 → 视为 profile 名本身
  if (!normalized.includes('/')) return { dshHome: null, profile: normalized };
  return null;
}

/**
 * 解释 dsh-plugin-reducer 的 stdout envelope（纯函数，便于单测）。
 *
 * @param {unknown} raw
 * @returns {import('../protocol/check.mjs').SecurityCheckResult}
 */
export function interpretEnvelope(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return skip(REDUCER_ID, Severity.MEDIUM,
      `dsh-plugin-reducer 输出的 JSON 不是 envelope 对象（实际：${typeName(raw)}），跳过故障最小化`);
  }

  if (raw.schemaVersion !== SUPPORTED_SCHEMA_VERSION) {
    return skip(REDUCER_ID, Severity.MEDIUM,
      `dsh-plugin-reducer envelope 的 schemaVersion=${JSON.stringify(raw.schemaVersion ?? null)} 不是受支持版本 ${SUPPORTED_SCHEMA_VERSION}，契约已变化，跳过故障最小化`);
  }

  const operation = typeof raw.operation === 'string' ? raw.operation : 'unknown';

  if (raw.ok === false) {
    const code = typeof raw.error?.code === 'string' ? raw.error.code : 'UNKNOWN';
    const message = typeof raw.error?.message === 'string' ? raw.error.message.slice(0, 120) : '';
    return skip(REDUCER_ID, Severity.MEDIUM,
      `dsh-plugin-reducer 未能完成归约（operation=${operation}, ok=false, code=${code}${message ? `：${message}` : ''}），跳过故障最小化`);
  }

  if (raw.ok !== true) {
    return skip(REDUCER_ID, Severity.MEDIUM,
      `dsh-plugin-reducer envelope 缺少布尔 ok（operation=${operation}），契约已变化，跳过故障最小化`);
  }

  const set = raw.report?.result?.minimalFailingSet;
  if (!Array.isArray(set)) {
    return skip(REDUCER_ID, Severity.MEDIUM,
      `dsh-plugin-reducer envelope ok=true 但 report.result.minimalFailingSet 缺失或不是数组（实际：${typeName(set)}），契约已变化，跳过故障最小化`);
  }

  if (set.length === 0) {
    // ok:true 在本工具语义下意味着「确实找到了最小故障集」（见文件头第 4 点），空集与契约矛盾
    return skip(REDUCER_ID, Severity.MEDIUM,
      'dsh-plugin-reducer envelope ok=true 但最小故障集为空——与「ok=true 即已找到最小故障集」的契约矛盾，跳过故障最小化（不外推为通过）');
  }

  const plugins = set.map(entry => (typeof entry === 'string' ? entry : JSON.stringify(entry)));
  const result = fail(
    REDUCER_ID,
    Severity.MEDIUM,
    `dsh-plugin-reducer 找到最小故障插件集（${plugins.length} 个）：${plugins.join(', ')}`,
    '移除或禁用故障插件集中的插件；该集合是 1-minimal 的，逐个排查会掩盖交互故障（A+B 组合失败）',
  );
  result.evidence = {
    schemaVersion: raw.schemaVersion,
    tool: raw.tool,
    operation,
    minimalFailingSet: plugins,
  };
  return result;
}

/**
 * 运行 dsh-plugin-reducer
 *
 * @param {string} profileDir - profile 目录（`<dshHome>/profiles/<name>`）或 profile 名
 * @param {'config'|'web'|'command'} [probeType] - 探针类型
 * @param {{isAvailable?: () => boolean, exec?: typeof execCapture, tmpRoot?: string}} [deps] - 测试注入点
 * @returns {Promise<import('../protocol/check.mjs').SecurityCheckResult>}
 */
export async function runReducer(profileDir, probeType = DEFAULT_PROBE, deps = {}) {
  const available = deps.isAvailable ? deps.isAvailable() : isAvailable();
  if (!available) {
    return skip(REDUCER_ID, Severity.MEDIUM,
      `dsh-plugin-reducer 未安装（PATH 中找不到 ${BIN}），跳过故障最小化；安装后可在启动故障时定位到最小插件集`);
  }

  const profile = deriveProfileArgs(profileDir);
  if (!profile) {
    return skip(REDUCER_ID, Severity.MEDIUM,
      `无法从 "${String(profileDir)}" 推断 profile 名（期望 <dshHome>/profiles/<name>）——dsh-plugin-reducer 的 --profile 收名字而非路径，跳过故障最小化`);
  }

  if (!PROBE_KINDS.has(probeType)) {
    return skip(REDUCER_ID, Severity.MEDIUM,
      `未知的探针类型 "${String(probeType)}"（支持：${[...PROBE_KINDS].join('/')}），跳过故障最小化`);
  }

  // --report 落在 os.tmpdir() 下的一次性目录（不再硬编码 /tmp），执行后清理
  let reportDir = null;
  let reportPath = null;
  try {
    reportDir = mkdtempSync(join(deps.tmpRoot ?? tmpdir(), 'dsh-security-reducer-'));
    reportPath = join(reportDir, 'reducer-report.json');
  } catch {
    reportDir = null; // 建不了临时目录就不传 --report：stdout 的 envelope 才是机器契约
    reportPath = null;
  }

  const args = [];
  if (profile.dshHome) args.push('--dsh-home', profile.dshHome);
  args.push('--profile', profile.profile, '--probe', probeType, '--json');
  if (reportPath) args.push('--report', reportPath, '--force');

  let res;
  try {
    const exec = deps.exec ?? execCapture;
    res = exec(BIN, args, { timeoutMs: 120000 });
  } finally {
    if (reportDir) rmSync(reportDir, { recursive: true, force: true });
  }

  // 上游退出码契约：0 = 归约完成；1 = 执行/归约失败；2 = 参数非法。
  // 后两者**仍然输出可解析的 envelope**（ok:false + error.code），所以先按契约判定退出码，
  // 再解析 stdout —— 只要 envelope 能解析出来，就走 interpretEnvelope 给出带原因的判断。
  const expectedExit = res.status === 0 || res.status === 1 || res.status === 2;
  const parsed = parseJson(res.stdout);

  if (!parsed.ok) {
    return skip(REDUCER_ID, Severity.MEDIUM,
      `dsh-plugin-reducer 的 stdout 无法解析为 JSON envelope（${describeFailure(res)}），跳过故障最小化`);
  }
  if (!expectedExit) {
    return skip(REDUCER_ID, Severity.MEDIUM,
      `dsh-plugin-reducer 以非预期退出码结束（${describeFailure(res)}），跳过故障最小化`);
  }

  return interpretEnvelope(parsed.value);
}

/**
 * dsh-plugin-reducer 集成检查对象
 */
export const pluginReducerCheck = {
  id: REDUCER_ID,
  name: 'plugin-reducer',
  severity: Severity.MEDIUM,
  phase: CheckPhase.LIFECYCLE,
  description: 'dsh-plugin-reducer 故障最小化',
  src: 'external',
  source: BIN,
  runner: (profileDir) => runReducer(profileDir),
};

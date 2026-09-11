/**
 * dsh-poison-guard 集成
 *
 * 如果 dsh-poison-guard 已安装（PATH 中可执行），自动集成到安全检查流程。
 * 复审修复：不再用 `npx 包名` 探测/执行；执行失败返回 skip 而不是伪装通过。
 *
 * 复审修复（docs/ecosystem-audit-2026-09.md §3(c) EXT-PG-1 / §4.4）——**真实发现曾被判为通过**：
 *
 * 1. 字段读错。工具的真实报告是
 *      `{ verdict: 'MALICIOUS'|'SUSPICIOUS'|'CLEAN', findings[{rule,severity,file,line,hint}], summary, stats }`
 *    （已核对上游 zoahdev/dsh-poison-guard@master `lib/index.js`：
 *     `const verdict = high.length > 0 ? 'MALICIOUS' : medium.length > 0 ? 'SUSPICIOUS' : 'CLEAN'`），
 *    旧代码读的是 `result.clean || result.vulnerabilities?.length === 0` —— 这两个字段工具都不产出，
 *    所以 `findings[]` 从未被使用。两种实际后果（均不会把发现报成 fail）：
 *      · 有发现 → 工具 exit 1 → execFileSync 抛异常 → catch 变成一句无信息的 skip
 *        （我们的协议里 skip 带 ok:true，只计入「跳过」，所以真发现在报告里彻底消失）；
 *      · 若同一份报告带 exit 0 返回 → 落到 `vulns = result.vulnerabilities || []` 分支，
 *        输出「检测到 0 个投毒模式：」——一个计数为空、毫无线索的 fail。
 *    现在一律以 `findings[]` 为准，`verdict` 只做交叉校验。
 *
 * 2. 退出码即契约。上游 `bin/poison-guard.mjs` 末行是
 *      `process.exit(report.verdict === 'CLEAN' ? 0 : 1)`
 *    也就是说**有发现时退出码是 1**。旧代码用 execFileSync，exit 1 会抛出异常，
 *    结构化 stdout 一起丢掉 → 真发现又退化成一句「执行失败，跳过」。
 *    现在 exit 0/1 都解析 stdout；其余退出码视为未知 → 显式 skip。
 *
 * 3. 「形状变了」必须 skip。verdict 缺失/未知、findings 存在但不是数组 —— 都是契约漂移，
 *    一律 skip 并带上原因，绝不外推成 pass。
 */

import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { skip, fail, pass } from '../protocol/check.mjs';
import { findExecutable, execCapture, parseJson, describeFailure, typeName } from './tool-exec.mjs';

export const POISON_GUARD_ID = 'EXT-PG-1';
const BIN = 'dsh-poison-guard';

/** 工具自报「干净」的 verdict（上游仅产出 'CLEAN'；大小写不敏感以容忍 shape 微调） */
const CLEAN_VERDICTS = new Set(['clean']);
/** 工具自报「有问题」的 verdict（上游：HIGH→MALICIOUS，MEDIUM→SUSPICIOUS） */
const BAD_VERDICTS = new Set(['malicious', 'suspicious']);

/**
 * 检测 dsh-poison-guard 是否可用（跨平台 PATH 扫描，不启动子进程）
 */
export function isAvailable() {
  return findExecutable(BIN) !== null;
}

/** 把工具 severity（HIGH/MEDIUM/LOW）映射到我们的词汇表 */
function normalizeSeverity(value) {
  const v = typeof value === 'string' ? value.trim().toLowerCase() : '';
  return v === 'high' || v === 'medium' || v === 'low' ? v : 'unknown';
}

/**
 * 把一条工具 finding 映射到我们的结果形状。
 * 工具 finding：`{ rule, severity, file, line, hint }`
 */
export function mapFinding(finding, index = 0) {
  const f = finding && typeof finding === 'object' && !Array.isArray(finding) ? finding : {};
  const line = Number.isFinite(f.line)
    ? f.line
    : (typeof f.line === 'string' && /^\d+$/.test(f.line) ? Number(f.line) : null);
  return {
    rule: typeof f.rule === 'string' && f.rule ? f.rule : `unknown-rule-${index + 1}`,
    severity: normalizeSeverity(f.severity),
    file: typeof f.file === 'string' && f.file ? f.file : null,
    line,
    hint: typeof f.hint === 'string' ? f.hint : '',
  };
}

/** 渲染一条已映射的 finding */
function renderFinding(f) {
  const where = f.file ? ` (${f.file}${f.line ? `:${f.line}` : ''})` : '';
  return `[${f.severity}] ${f.rule}: ${f.hint || '(无 hint)'}${where}`;
}

/**
 * 解释 dsh-poison-guard 的 JSON 报告（纯函数，便于单测）。
 *
 * 判定优先级：
 *   findings 非空 → FAIL（不管 verdict 说什么）
 *   findings 为空/缺失 + verdict=CLEAN → PASS
 *   findings 为空 + verdict=MALICIOUS/SUSPICIOUS → FAIL（非 CLEAN 的 verdict 永不判 pass）
 *   其余（verdict 缺失/未知、findings 类型异常、不是对象）→ skip + 原因
 *
 * @param {unknown} raw
 * @returns {import('../protocol/check.mjs').SecurityCheckResult}
 */
export function interpretReport(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    return skip(POISON_GUARD_ID, Severity.HIGH,
      `dsh-poison-guard 输出的 JSON 不是对象（实际：${typeName(raw)}），无法解释报告，跳过投毒扫描`);
  }

  const verdict = typeof raw.verdict === 'string' ? raw.verdict.trim() : null;
  const hasFindingsKey = raw.findings !== undefined;

  if (hasFindingsKey && !Array.isArray(raw.findings)) {
    return skip(POISON_GUARD_ID, Severity.HIGH,
      `dsh-poison-guard 输出的 findings 不是数组（实际：${typeName(raw.findings)}），契约已变化，跳过投毒扫描`);
  }

  const findings = Array.isArray(raw.findings) ? raw.findings : [];

  if (findings.length > 0) {
    const mapped = findings.map((f, i) => mapFinding(f, i));
    const shown = mapped.slice(0, 10).map(renderFinding).join('\n');
    const more = mapped.length > 10 ? `\n…另有 ${mapped.length - 10} 条未展开` : '';
    const verdictNote = verdict ? `，verdict=${verdict}` : '';
    const result = fail(
      POISON_GUARD_ID,
      Severity.HIGH,
      `dsh-poison-guard 检测到 ${mapped.length} 个投毒发现${verdictNote}：\n${shown}${more}`,
      '检查相关插件源码，移除恶意/混淆代码；保留安装脚本审计结果作为 pre-install 阻断依据',
      ['#2961', '#5498'],
    );
    result.evidence = { verdict, findings: mapped };
    return result;
  }

  // findings 为空 → 只能靠 verdict 判定
  if (verdict === null) {
    return skip(POISON_GUARD_ID, Severity.HIGH,
      'dsh-poison-guard 输出既无 findings 也无 verdict（契约已变化），跳过投毒扫描（不外推为通过）');
  }

  const normalized = verdict.toLowerCase();
  if (CLEAN_VERDICTS.has(normalized)) {
    const result = pass(POISON_GUARD_ID, Severity.HIGH,
      `dsh-poison-guard 扫描通过：verdict=${verdict}，无 findings`);
    result.evidence = { verdict, findings: [] };
    return result;
  }
  if (BAD_VERDICTS.has(normalized)) {
    const result = fail(
      POISON_GUARD_ID,
      Severity.HIGH,
      `dsh-poison-guard 报告 verdict=${verdict} 但未给出 findings，按非 CLEAN 判定为发现`,
      '重新运行 dsh-poison-guard 获取完整 findings，或人工审查该插件源码',
    );
    result.evidence = { verdict, findings: [] };
    return result;
  }

  return skip(POISON_GUARD_ID, Severity.HIGH,
    `dsh-poison-guard 输出了无法识别的 verdict=${verdict}（已知：CLEAN/MALICIOUS/SUSPICIOUS），跳过投毒扫描`);
}

/**
 * 运行 dsh-poison-guard 扫描
 * @param {string} targetPath - 要扫描的目录或包路径
 * @param {{isAvailable?: () => boolean, exec?: typeof execCapture}} [deps] - 测试注入点
 * @returns {Promise<import('../protocol/check.mjs').SecurityCheckResult>}
 */
export async function runScan(targetPath, deps = {}) {
  const available = deps.isAvailable ? deps.isAvailable() : isAvailable();
  if (!available) {
    return skip(POISON_GUARD_ID, Severity.HIGH,
      `dsh-poison-guard 未安装（PATH 中找不到 ${BIN}），跳过投毒扫描；安装后可覆盖 pre-install 投毒检测`);
  }

  if (!targetPath) {
    return skip(POISON_GUARD_ID, Severity.HIGH, '未提供待扫描的插件目录，跳过投毒扫描');
  }

  const exec = deps.exec ?? execCapture;
  const res = exec(BIN, ['scan', String(targetPath), '--json'], { timeoutMs: 60000 });

  // 上游退出码契约：0 = CLEAN，1 = 至少一个发现；其余（2 = 用法错误）为未知
  if (res.status !== 0 && res.status !== 1) {
    return skip(POISON_GUARD_ID, Severity.HIGH,
      `dsh-poison-guard 以非预期退出码结束（${describeFailure(res)}），跳过投毒扫描`);
  }

  const parsed = parseJson(res.stdout);
  if (!parsed.ok) {
    return skip(POISON_GUARD_ID, Severity.HIGH,
      `dsh-poison-guard 的 stdout 无法解析为 JSON（${describeFailure(res)}），跳过投毒扫描`);
  }

  return interpretReport(parsed.value);
}

/**
 * dsh-poison-guard 集成检查对象
 */
export const poisonGuardCheck = {
  id: POISON_GUARD_ID,
  name: 'poison-scan',
  severity: Severity.HIGH,
  phase: CheckPhase.POST_INSTALL,
  description: 'dsh-poison-guard 投毒扫描（AST + 反混淆）',
  src: 'external',
  source: BIN,
  runner: (targetPath) => runScan(targetPath),
};

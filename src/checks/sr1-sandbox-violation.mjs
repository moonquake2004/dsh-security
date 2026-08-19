/**
 * SR1: Sandbox Violation — 沙箱逃逸检测
 *
 * 分析会话日志中的工具调用，检测潜在的沙箱逃逸行为：
 * - 写操作超出 workspace 范围
 * - 访问系统级资源（/etc, /proc, 环境变量）
 * - 已知逃逸模式匹配（#1769 mount remount 等）
 *
 * Severity: CRITICAL
 * Phase: RUNTIME
 */

import { readFileSync, existsSync, createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail } from '../protocol/check.mjs';

/** 已知逃逸模式（#1769 及同类） */
const ESCAPE_PATTERNS = [
  { name: 'mount remount', regex: /mount\s+.*-o\s+remount.*rw/gi, severity: 'critical', ref: '#1769' },
  { name: 'chroot escape', regex: /chroot\s+\//gi, severity: 'critical', ref: null },
  { name: 'nsenter', regex: /nsenter\s+/gi, severity: 'critical', ref: null },
  { name: 'unshare', regex: /unshare\s+/gi, severity: 'high', ref: null },
];

/** 系统资源访问模式 */
const SYSTEM_RESOURCE_PATTERNS = [
  { name: '/etc access', regex: /\/etc\/(passwd|shadow|sudoers|hosts)/gi, severity: 'high' },
  { name: '/proc access', regex: /\/proc\/(self|1|environ|cmdline)/gi, severity: 'high' },
  { name: 'env dump', regex: /env\b|printenv|set\b.*\|/gi, severity: 'medium' },
  { name: 'sudo usage', regex: /sudo\s+/gi, severity: 'high' },
  { name: 'curl/wget to unknown', regex: /curl\s+.*\|\s*(bash|sh|node)|wget\s+.*\|\s*(bash|sh|node)/gi, severity: 'critical' },
];

/** 工作区逃逸路径模式 */
const WORKSPACE_ESCAPE_PATTERNS = [
  { name: 'write to /tmp', regex: /writeFileSync|writeFile|fs\.write|echo\s+.*>\s*\/tmp/gi, severity: 'low' },
  { name: 'write to home', regex: /writeFileSync|writeFile.*\/Users\/|\/home\//gi, severity: 'low' },
  { name: 'pipe to shell', regex: /\|\s*(bash|sh|zsh)\b/gi, severity: 'high' },
  { name: 'exec subprocess', regex: /child_process|execSync|spawnSync|exec\b/gi, severity: 'medium' },
];

/**
 * 从一行 JSONL 中提取工具调用信息
 */
function extractToolCalls(line) {
  try {
    const event = JSON.parse(line);
    if (event.type !== 'tool/call' && event.type !== 'tool/result') return [];

    const calls = [];
    const data = event.data || {};
    const name = data.name || data.tool || '';
    const args = data.args || data.input || {};
    const text = typeof args === 'string' ? args : JSON.stringify(args);

    calls.push({
      type: event.type,
      name,
      text,
      seq: event.seq,
      turn: event.turn,
    });
    return calls;
  } catch {
    return [];
  }
}

/**
 * 扫描文本中的危险模式
 */
function scanPatterns(text, patterns) {
  const findings = [];
  for (const pattern of patterns) {
    const matches = text.matchAll(new RegExp(pattern.regex.source, 'gi'));
    for (const match of matches) {
      findings.push({
        type: pattern.name,
        severity: pattern.severity,
        ref: pattern.ref || null,
        snippet: match[0].slice(0, 60),
      });
    }
  }
  return findings;
}

/**
 * SR1 检查：分析会话日志中的沙箱逃逸行为
 * @param {string} sessionFile - 会话日志文件路径
 * @returns {Promise<import('../protocol/check.mjs').SecurityCheckResult>}
 */
export async function run(sessionFile) {
  const id = 'SR1';

  if (!sessionFile || !existsSync(sessionFile)) {
    return pass(id, Severity.CRITICAL, '无会话日志，跳过运行时安全检查');
  }

  if (sessionFile.endsWith('.zstd')) {
    return pass(id, Severity.CRITICAL, 'zstd 压缩的会话文件需先解压再检查');
  }

  const findings = [];
  let lineCount = 0;

  const fileStream = createReadStream(sessionFile, { encoding: 'utf8' });
  const rl = createInterface({ input: fileStream, crlfDelay: Infinity });

  for await (const line of rl) {
    lineCount++;
    if (!line.trim()) continue;

    const calls = extractToolCalls(line);
    for (const call of calls) {
      // 扫描工具参数中的危险模式
      const allPatterns = [...ESCAPE_PATTERNS, ...SYSTEM_RESOURCE_PATTERNS, ...WORKSPACE_ESCAPE_PATTERNS];
      const textFindings = scanPatterns(call.text, allPatterns);
      for (const f of textFindings) {
        findings.push({
          ...f,
          line: lineCount,
          tool: call.name,
          seq: call.seq,
          turn: call.turn,
        });
      }
    }
  }

  if (findings.length === 0) {
    return pass(id, Severity.CRITICAL, `扫描 ${lineCount} 行会话日志，未检测到沙箱逃逸行为`);
  }

  // 按严重度分组
  const bySeverity = {};
  for (const f of findings) {
    if (!bySeverity[f.severity]) bySeverity[f.severity] = [];
    bySeverity[f.severity].push(f);
  }

  const summary = Object.entries(bySeverity)
    .map(([sev, items]) => `${sev}: ${items.length}`)
    .join(', ');

  const details = findings
    .slice(0, 10)
    .map(f => `[${f.severity}] 行${f.line} ${f.tool} — ${f.type}（${f.snippet}）${f.ref ? ' [' + f.ref + ']' : ''}`)
    .join('\n');

  const criticalCount = findings.filter(f => f.severity === 'critical').length;
  const overallSeverity = criticalCount > 0 ? Severity.CRITICAL : Severity.HIGH;

  const fix = criticalCount > 0
    ? '检测到 CRITICAL 级别沙箱逃逸行为，立即检查相关工具和插件'
    : '检查相关工具调用是否在预期的沙箱策略内';

  const refs = [...new Set(findings.filter(f => f.ref).map(f => f.ref))];

  return fail(id, overallSeverity,
    `检测到 ${findings.length} 个潜在沙箱逃逸行为（${summary}）：\n${details}`,
    fix,
    refs
  );
}

export const sr1Check = {
  id: 'SR1',
  name: 'sandbox-violation',
  severity: Severity.CRITICAL,
  phase: CheckPhase.RUNTIME,
  description: '沙箱逃逸行为检测（会话日志分析）',
  src: 'builtin',
  runner: (sessionFile) => run(sessionFile),
};

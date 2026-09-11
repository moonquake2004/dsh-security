/**
 * SR1: Sandbox Violation — 沙箱逃逸检测
 *
 * 分析会话日志中的工具调用（tool/call），检测潜在的沙箱逃逸行为：
 * - 访问系统级资源（/etc, /proc）
 * - 已知逃逸模式匹配（#1769 mount remount 等）
 * - 管道执行远程脚本
 *
 * 支持明文与 zstd 压缩会话日志（session-reader）。
 *
 * Severity: CRITICAL
 * Phase: RUNTIME
 */

import { existsSync } from 'node:fs';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail, skip } from '../protocol/check.mjs';
import { scanSessionLines, extractEvent, isShellTool } from '../session-reader.mjs';

/** 已知逃逸模式（#1769 及同类） */
/** 下载即执行：curl/wget 管道进解释器 —— 与逃逸同级的高信号规则（其余系统资源规则不算发现） */
const HIGH_SIGNAL_DOWNLOAD = { name: 'curl/wget to shell', regex: /(?:curl|wget)\s+[^\n|"']{1,160}\|\s*(?:bash|sh|zsh|node)\b/gi, severity: 'critical', ref: null };

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
  // 复审修复：旧正则 /env\b|set\b.*\|/ 几乎命中一切文本；改为命令位置的 env/printenv 转储
  { name: 'env dump', regex: /(?:^|["'|;&]\s*)(?:printenv|env)\s*(?:[|;"']|$)/gm, severity: 'medium' },
  { name: 'sudo usage', regex: /sudo\s+/gi, severity: 'high' },
  { name: 'curl/wget to unknown', regex: /curl\s+.*\|\s*(bash|sh|node)|wget\s+.*\|\s*(bash|sh|node)/gi, severity: 'critical' },
];

/** 工作区逃逸路径模式 */
const WORKSPACE_ESCAPE_PATTERNS = [
  { name: 'write to /tmp', regex: /writeFileSync|writeFile|fs\.write|echo\s+.*>\s*\/tmp/gi, severity: 'low' },
  { name: 'write to home', regex: /writeFileSync|writeFile.*\/Users\/|\/home\//gi, severity: 'low' },
  { name: 'pipe to shell', regex: /\|\s*(bash|sh|zsh)\b/gi, severity: 'high' },
  // 复审修复：去掉过宽的 exec\b（命中 "execute" 等普通词），保留具体进程 API
  { name: 'exec subprocess', regex: /child_process|execSync|spawnSync/gi, severity: 'medium' },
];

/**
 * 从一行 JSONL 中提取工具调用信息（只看 tool/call：result 是数据不是行为）
 */
function extractToolCalls(line) {
  try {
    const e = extractEvent(JSON.parse(line));
    if (e.kind === 'other') return [];
    return [{ type: e.type, name: e.name || '', text: e.argsText || e.resultText || '', seq: e.seq, turn: e.turn, callId: e.callId }];
  } catch { return []; }
}

/**
 * 扫描文本中的危险模式
 */
function scanPatterns(text, patterns) {
  const findings = [];
  for (const pattern of patterns) {
    const flags = [...new Set((pattern.regex.flags + 'g').split(''))].join('');
    const matches = text.matchAll(new RegExp(pattern.regex.source, flags));
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
 * @param {string} sessionFile - 会话日志文件路径（.jsonl 或 .jsonl.zstd）
 * @returns {Promise<import('../protocol/check.mjs').SecurityCheckResult>}
 */
export async function run(sessionFile) {
  const id = 'SR1';

  if (!sessionFile || !existsSync(sessionFile)) {
    return skip(id, Severity.CRITICAL, '无会话日志，跳过运行时安全检查');
  }

  const findings = [];
  let contextualCount = 0;
  let lineCount = 0;

  try {
    lineCount = await scanSessionLines(sessionFile, (line, lineNo) => {
      if (!line.trim()) return;
      const calls = extractToolCalls(line);
      for (const call of calls) {
        // 只作用于命令执行类工具（#2026-09：文档工具里"引用"路径会被误判为逃逸行为）
        if (!isShellTool(call.name, call.text)) continue;
        // 只把"逃逸原语"计为发现（chroot/nsenter/unshare/remount、下载即执行、管道进 shell）。
        // 其余规则（读 /etc、/proc、env dump、sudo、写 /tmp 或 home、提及 child_process）
        // 在日常 agent 工作里普遍出现，静默计入 contextual 而**不抬严重级**（2026-09 实测：不区分会误报 361 处）。
        const decisive = [...ESCAPE_PATTERNS, HIGH_SIGNAL_DOWNLOAD];
        const contextual = [...SYSTEM_RESOURCE_PATTERNS, ...WORKSPACE_ESCAPE_PATTERNS];
        const seenRules = new Set(); // 同一事件内同一规则只记一次（文本里重复提及不再放大计数）
        for (const f of scanPatterns(call.text, decisive)) {
          if (seenRules.has(f.type)) continue;
          seenRules.add(f.type);
          findings.push({ ...f, line: lineNo, tool: call.name, seq: call.seq, turn: call.turn });
        }
        for (const _ of scanPatterns(call.text, contextual)) contextualCount++;
      }
    });
  } catch (e) {
    if (e.code === 'ZSTD_UNAVAILABLE') {
      return skip(id, Severity.CRITICAL, 'zstd 命令不可用，无法解压压缩会话日志，跳过沙箱逃逸检测');
    }
    throw e;
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
  description: '沙箱逃逸行为检测（会话日志分析，支持 zstd）',
  src: 'builtin',
  runner: (sessionFile) => run(sessionFile),
};

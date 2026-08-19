/**
 * SR3: Data Exfiltration — 数据外泄检测
 *
 * 分析会话日志中的工具调用，检测潜在的数据外泄行为：
 * - 大量文件读取后接网络请求
 * - 凭据转发（将密钥传递给外部工具）
 * - 异常的数据流模式
 *
 * Severity: HIGH
 * Phase: RUNTIME
 */

import { existsSync, createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail } from '../protocol/check.mjs';

/** 凭据转发模式 */
const CREDENTIAL_FORWARD_PATTERNS = [
  { name: 'API key in command', regex: /sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|AKIA[0-9A-Z]{16}/g, severity: 'high' },
  { name: 'Token in URL', regex: /https?:\/\/[^ ]*token=[^ &]+/gi, severity: 'high' },
  { name: 'Bearer in command', regex: /Bearer\s+[a-zA-Z0-9._-]{20,}/gi, severity: 'high' },
];

/** 网络外发模式 */
const NETWORK_EXFIL_PATTERNS = [
  { name: 'curl POST', regex: /curl\s+.*-X\s*POST|curl\s+.*--data/gi, severity: 'medium' },
  { name: 'wget POST', regex: /wget\s+.*--post-data/gi, severity: 'medium' },
  { name: 'fetch API', regex: /fetch\s*\(|\.post\s*\(/gi, severity: 'low' },
  { name: 'HTTP request with data', regex: /http\.request|https\.request|axios\.post/gi, severity: 'low' },
];

/** 大量数据读取模式 */
const BULK_READ_PATTERNS = [
  { name: 'read entire file', regex: /readFileSync|readFile\b|cat\s+[^|]+$/gm, severity: 'low' },
  { name: 'directory listing', regex: /readdirSync|readdir\b|ls\s+-[la]*/gi, severity: 'low' },
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

    calls.push({ type: event.type, name, text, seq: event.seq, turn: event.turn });
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
        snippet: match[0].slice(0, 60),
      });
    }
  }
  return findings;
}

/**
 * SR3 检查：分析会话日志中的数据外泄行为
 * @param {string} sessionFile - 会话日志文件路径
 * @returns {Promise<import('../protocol/check.mjs').SecurityCheckResult>}
 */
export async function run(sessionFile) {
  const id = 'SR3';

  if (!sessionFile || !existsSync(sessionFile)) {
    return pass(id, Severity.HIGH, '无会话日志，跳过数据外泄检查');
  }

  if (sessionFile.endsWith('.zstd')) {
    return pass(id, Severity.HIGH, 'zstd 压缩的会话文件需先解压再检查');
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
      // 扫描凭据转发
      const credFindings = scanPatterns(call.text, CREDENTIAL_FORWARD_PATTERNS);
      for (const f of credFindings) {
        findings.push({ ...f, line: lineCount, tool: call.name, category: 'credential-forward' });
      }

      // 扫描网络外发
      const netFindings = scanPatterns(call.text, NETWORK_EXFIL_PATTERNS);
      for (const f of netFindings) {
        findings.push({ ...f, line: lineCount, tool: call.name, category: 'network-exfil' });
      }
    }
  }

  if (findings.length === 0) {
    return pass(id, Severity.HIGH, `扫描 ${lineCount} 行会话日志，未检测到数据外泄行为`);
  }

  // 按类别分组
  const byCategory = {};
  for (const f of findings) {
    if (!byCategory[f.category]) byCategory[f.category] = [];
    byCategory[f.category].push(f);
  }

  const summary = Object.entries(byCategory)
    .map(([cat, items]) => `${cat}: ${items.length}`)
    .join(', ');

  const details = findings
    .slice(0, 10)
    .map(f => `[${f.severity}] 行${f.line} ${f.tool} — ${f.type}（${f.snippet}）`)
    .join('\n');

  const highCount = findings.filter(f => f.severity === 'high').length;
  const overallSeverity = highCount > 0 ? Severity.HIGH : Severity.MEDIUM;

  const fix = highCount > 0
    ? '检测到凭据转发或敏感数据外发，检查相关工具是否在传递密钥给外部服务'
    : '检查网络请求是否在预期的数据流范围内';

  return fail(id, overallSeverity,
    `检测到 ${findings.length} 个潜在数据外泄行为（${summary}）：\n${details}`,
    fix,
    ['#962']
  );
}

export const sr3Check = {
  id: 'SR3',
  name: 'data-exfiltration',
  severity: Severity.HIGH,
  phase: CheckPhase.RUNTIME,
  description: '数据外泄行为检测（会话日志分析）',
  src: 'builtin',
  runner: (sessionFile) => run(sessionFile),
};

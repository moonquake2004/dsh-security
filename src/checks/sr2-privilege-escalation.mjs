/**
 * SR2: Privilege Escalation — 权限提升检测
 *
 * 分析会话日志中的工具调用（tool/call）中的权限提升行为：
 * - sudo/doas 使用
 * - 文件权限变更（chmod/chown）
 * - setuid/setgid、Linux capability 操作
 *
 * 支持明文与 zstd 压缩会话日志（session-reader）。
 *
 * Severity: HIGH
 * Phase: RUNTIME
 */

import { existsSync } from 'node:fs';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail, skip } from '../protocol/check.mjs';
import { scanSessionLines } from '../session-reader.mjs';

const PRIVILEGE_PATTERNS = [
  { name: 'sudo usage', regex: /sudo\s+/gi, severity: 'high' },
  { name: 'doas usage', regex: /\bdoas\s+/gi, severity: 'high' },
  { name: 'chmod', regex: /chmod\s+[^/]*\s+[0-7]*7[0-7][0-7]/gi, severity: 'medium' },
  { name: 'chown', regex: /chown\s+/gi, severity: 'medium' },
  { name: 'setuid', regex: /setuid|setgid/gi, severity: 'high' },
  { name: 'capability', regex: /cap_|CAP_/gi, severity: 'high' },
];

function extractToolCalls(line) {
  try {
    const event = JSON.parse(line);
    if (event.type !== 'tool/call') return [];
    const data = event.data || {};
    return [{ name: data.name || data.tool || '', text: JSON.stringify(data.args || data.input || {}), seq: event.seq }];
  } catch { return []; }
}

export async function run(sessionFile) {
  const id = 'SR2';
  if (!sessionFile || !existsSync(sessionFile)) return pass(id, Severity.HIGH, '无会话文件，跳过权限提升检测');

  const findings = [];
  let lineCount = 0;

  try {
    lineCount = await scanSessionLines(sessionFile, (line, lineNo) => {
      if (!line.trim()) return;
      for (const call of extractToolCalls(line)) {
        for (const pattern of PRIVILEGE_PATTERNS) {
          for (const match of call.text.matchAll(new RegExp(pattern.regex.source, 'gi'))) {
            findings.push({ type: pattern.name, severity: pattern.severity, line: lineNo, tool: call.name, snippet: match[0].slice(0, 40) });
          }
        }
      }
    });
  } catch (e) {
    if (e.code === 'ZSTD_UNAVAILABLE') {
      return skip(id, Severity.HIGH, 'zstd 命令不可用，无法解压压缩会话日志，跳过权限提升检测');
    }
    throw e;
  }

  if (findings.length === 0) return pass(id, Severity.HIGH, `扫描 ${lineCount} 行，未检测到权限提升行为`);

  const details = findings.slice(0, 10).map(f => `[${f.severity}] 行${f.line} ${f.tool} — ${f.type}: ${f.snippet}`).join('\n');
  const highCount = findings.filter(f => f.severity === 'high').length;
  return fail(id, highCount > 0 ? Severity.HIGH : Severity.MEDIUM,
    `检测到 ${findings.length} 个权限提升行为：\n${details}`,
    '检查相关工具调用是否在预期的权限范围内'
  );
}

export const sr2Check = { id: 'SR2', name: 'privilege-escalation', severity: Severity.HIGH, phase: CheckPhase.RUNTIME, description: '权限提升行为检测（支持 zstd）', src: 'builtin', runner: (f) => run(f) };

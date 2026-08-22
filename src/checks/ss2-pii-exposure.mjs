/**
 * SS2: PII Exposure — PII 数据暴露检测
 *
 * 扫描会话日志中的个人身份信息（PII）：
 * - 邮箱地址
 * - 电话号码
 * - 身份证号码
 * - IP 地址
 *
 * Severity: MEDIUM
 * Phase: POST_INSTALL
 */

import { existsSync } from 'node:fs';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail, skip } from '../protocol/check.mjs';
import { scanSessionLines } from '../session-reader.mjs';

const PII_PATTERNS = [
  { name: 'email', regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, severity: 'medium' },
  { name: 'phone', regex: /(\+?86)?1[3-9]\d{9}/g, severity: 'medium' },
  { name: 'ID card', regex: /[1-9]\d{5}(19|20)\d{2}(0[1-9]|1[0-2])(0[1-9]|[12]\d|3[01])\d{3}[\dXx]/g, severity: 'high' },
  { name: 'IPv4', regex: /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g, severity: 'low' },
];

/** PII 掩码：保留类型可辨识度，不回显完整个人信息 */
function maskPII(s) {
  if (s.length <= 6) return `***(${s.length} chars)`;
  return `${s.slice(0, 2)}***${s.slice(-2)}(${s.length} chars)`;
}

function extractTextFromLine(line) {
  try {
    const event = JSON.parse(line);
    const texts = [];
    function extract(obj) {
      if (typeof obj === 'string') texts.push(obj);
      else if (Array.isArray(obj)) obj.forEach(extract);
      else if (obj && typeof obj === 'object') Object.values(obj).forEach(extract);
    }
    extract(event.data || event);
    return texts.join(' ');
  } catch { return ''; }
}

export async function run(sessionFile) {
  const id = 'SS2';
  if (!sessionFile || !existsSync(sessionFile)) return pass(id, Severity.MEDIUM, '无会话文件，跳过 PII 检测');

  const findings = [];
  let lineCount = 0;

  try {
    lineCount = await scanSessionLines(sessionFile, (line, lineNo) => {
      if (!line.trim()) return;
      const text = extractTextFromLine(line);
      for (const pattern of PII_PATTERNS) {
        for (const match of text.matchAll(new RegExp(pattern.regex.source, 'g'))) {
          findings.push({ type: pattern.name, severity: pattern.severity, line: lineNo, snippet: maskPII(match[0]) });
        }
      }
    });
  } catch (e) {
    if (e.code === 'ZSTD_UNAVAILABLE') {
      return skip(id, Severity.MEDIUM, 'zstd 命令不可用，无法解压压缩会话日志，跳过 PII 检测');
    }
    throw e;
  }

  if (findings.length === 0) return pass(id, Severity.MEDIUM, `扫描 ${lineCount} 行，未检测到 PII 暴露`);

  const byType = {};
  for (const f of findings) { if (!byType[f.type]) byType[f.type] = 0; byType[f.type]++; }
  const summary = Object.entries(byType).map(([t, c]) => `${t}: ${c}`).join(', ');
  const details = findings.slice(0, 10).map(f => `行${f.line} — ${f.type}: ${f.snippet}`).join('\n');
  return fail(id, Severity.MEDIUM, `检测到 ${findings.length} 个 PII 暴露（${summary}）：\n${details}`, '使用 dsh-redact 脱敏后再分享会话日志');
}

export const ss2Check = { id: 'SS2', name: 'pii-exposure', severity: Severity.MEDIUM, phase: CheckPhase.POST_INSTALL, description: 'PII 数据暴露检测', src: 'builtin', runner: (f) => run(f) };

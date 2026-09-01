/**
 * SS1: Credential Leak — 会话日志凭据泄露检测
 *
 * 扫描 session.jsonl（或 .zstd 压缩）中的敏感凭据（API key/token/私钥）。
 *
 * 复审修复：
 * - snippet 不再回显凭据本体（旧实现输出前 20+后 4 字符，检测器自己泄露凭据）
 * - 移除"前几行含 [REDACTED]/*** 即整体跳过"的弱启发（一行 markdown 分隔线就能让整个文件免检）
 *
 * Severity: CRITICAL
 * Phase: POST_INSTALL
 */

import { existsSync } from 'node:fs';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail, skip } from '../protocol/check.mjs';
import { scanSessionLines } from '../session-reader.mjs';

/** 凭据模式 */
const CREDENTIAL_PATTERNS = [
  { name: 'OpenAI API Key', regex: /sk-[a-zA-Z0-9]{20,}/g },
  { name: 'GitHub PAT', regex: /ghp_[a-zA-Z0-9]{36}/g },
  { name: 'GitHub Fine-grained PAT', regex: /github_pat_[a-zA-Z0-9_]{20,}/g },
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g },
  { name: 'Slack Token', regex: /xox[baprs]-[a-zA-Z0-9-]+/g },
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z_-]{35}/g },
  { name: 'PEM Private Key', regex: /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/g },
  { name: 'Bearer Token', regex: /Bearer\s+[a-zA-Z0-9._-]{20,}/g },
  { name: 'Basic Auth', regex: /Basic\s+[a-zA-Z0-9+/=]{20,}/g },
];

/** 掩码：只保留极短前缀 + 长度信息，绝不回显凭据内容 */
function maskSecret(s) {
  if (s.length <= 8) return `***(${s.length} chars)`;
  return `${s.slice(0, 4)}***(${s.length} chars)`;
}

/**
 * 从一行 JSONL 中提取文本内容
 */
function extractTextFromLine(line) {
  try {
    const event = JSON.parse(line);
    const texts = [];
    function extract(obj) {
      if (typeof obj === 'string') {
        texts.push(obj);
      } else if (Array.isArray(obj)) {
        for (const item of obj) extract(item);
      } else if (obj && typeof obj === 'object') {
        for (const val of Object.values(obj)) extract(val);
      }
    }
    extract(event.data || event);
    return texts.join(' ');
  } catch {
    return '';
  }
}

function scanLine(text) {
  const findings = [];
  for (const pattern of CREDENTIAL_PATTERNS) {
    const matches = text.matchAll(new RegExp(pattern.regex.source, 'g'));
    for (const match of matches) {
      findings.push({
        type: pattern.name,
        snippet: maskSecret(match[0]),
      });
    }
  }
  return findings;
}

/**
 * SS1 检查：扫描会话日志中的凭据泄露
 * @param {string} sessionFile - session.jsonl 或 session.jsonl.zstd 路径
 * @returns {Promise<import('../protocol/check.mjs').SecurityCheckResult>}
 */
export async function run(sessionFile) {
  const id = 'SS1';

  if (!sessionFile || !existsSync(sessionFile)) {
    return pass(id, Severity.CRITICAL, '会话文件不存在，跳过检查');
  }

  const findings = [];
  let lineCount = 0;

  try {
    lineCount = await scanSessionLines(sessionFile, (line, lineNo) => {
      if (!line.trim()) return;
      const text = extractTextFromLine(line);
      if (!text) return;
      for (const f of scanLine(text)) {
        findings.push({ ...f, line: lineNo });
      }
    });
  } catch (e) {
    if (e.code === 'ZSTD_UNAVAILABLE') {
      return skip(id, Severity.CRITICAL, 'zstd 命令不可用，无法解压压缩会话日志，跳过凭据泄露检测');
    }
    throw e;
  }

  if (findings.length === 0) {
    return pass(id, Severity.CRITICAL, `扫描 ${lineCount} 行会话日志，未检测到凭据泄露`);
  }

  // 按类型聚合
  const byType = {};
  for (const f of findings) {
    if (!byType[f.type]) byType[f.type] = 0;
    byType[f.type]++;
  }

  const summary = Object.entries(byType)
    .map(([type, count]) => `${type}: ${count}`)
    .join(', ');

  const details = findings
    .slice(0, 10)
    .map(f => `行 ${f.line} — ${f.type}（${f.snippet}）`)
    .join('\n');

  const fix = '轮换泄露的密钥（不可逆），然后清理会话日志：可用 zoahdev/dsh-redact（GitHub: github.com/zoahdev/dsh-redact）或手动删除含密钥的行';

  return fail(id, Severity.CRITICAL, `检测到 ${findings.length} 个凭据泄露（${summary}）：\n${details}`, fix, ['#962']);
}

export const ss1Check = {
  id: 'SS1',
  name: 'credential-leak',
  severity: Severity.CRITICAL,
  phase: CheckPhase.POST_INSTALL,
  description: '会话日志凭据泄露检测（支持 zstd，结果自动掩码）',
  src: 'builtin',
  runner: (sessionFile) => run(sessionFile),
};

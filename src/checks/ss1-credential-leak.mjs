/**
 * SS1: Credential Leak — 会话日志凭据泄露检测
 *
 * 扫描 session.jsonl 中的敏感凭据（API key/token/私钥）。
 * 检查是否已通过 dsh-redact 脱敏。
 *
 * Severity: CRITICAL
 * Phase: POST_INSTALL
 */

import { readFileSync, existsSync } from 'node:fs';
import { createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail } from '../protocol/check.mjs';

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

/**
 * 从一行 JSONL 中提取文本内容
 */
function extractTextFromLine(line) {
  try {
    const event = JSON.parse(line);
    // 递归提取所有字符串值
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

/**
 * 扫描单行中的凭据
 */
function scanLine(text) {
  const findings = [];
  for (const pattern of CREDENTIAL_PATTERNS) {
    const matches = text.matchAll(new RegExp(pattern.regex.source, 'g'));
    for (const match of matches) {
      findings.push({
        type: pattern.name,
        snippet: match[0].slice(0, 20) + '...' + match[0].slice(-4),
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

  if (!existsSync(sessionFile)) {
    return pass(id, Severity.CRITICAL, '会话文件不存在，跳过检查');
  }

  // 检查是否是 zstd 压缩的（需要先解压）
  if (sessionFile.endsWith('.zstd')) {
    return pass(id, Severity.CRITICAL, 'zstd 压缩的会话文件需先解压再检查（或使用 dsh-redact 直接处理）');
  }

  // 检查是否已通过 dsh-redact 脱敏
  try {
    const firstLines = createReadStream(sessionFile, { encoding: 'utf8' });
    const rl = createInterface({ input: firstLines, crlfDelay: Infinity });
    let alreadyRedacted = false;
    let checkCount = 0;
    for await (const line of rl) {
      if (checkCount++ > 5) break;
      if (line.includes('[REDACTED]') || line.includes('[redacted]') || line.includes('***')) {
        alreadyRedacted = true;
        break;
      }
    }
    firstLines.destroy();
    if (alreadyRedacted) {
      return pass(id, Severity.CRITICAL, '会话文件似乎已通过 dsh-redact 脱敏');
    }
  } catch { /* 继续正常检查 */ }

  const findings = [];
  let lineCount = 0;

  const fileStream = createReadStream(sessionFile, { encoding: 'utf8' });
  const rl = createInterface({ input: fileStream, crlfDelay: Infinity });

  for await (const line of rl) {
    lineCount++;
    if (!line.trim()) continue;
    const text = extractTextFromLine(line);
    if (!text) continue;
    const lineFindings = scanLine(text);
    for (const f of lineFindings) {
      findings.push({ ...f, line: lineCount });
    }
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

  const fix = '使用 dsh-redact 脱敏后再分享会话日志：npx dsh-redact <session.jsonl> --out redacted.jsonl';

  return fail(id, Severity.CRITICAL, `检测到 ${findings.length} 个凭据泄露（${summary}）：\n${details}`, fix, ['#962']);
}

export const ss1Check = {
  id: 'SS1',
  name: 'credential-leak',
  severity: Severity.CRITICAL,
  phase: CheckPhase.POST_INSTALL,
  description: '会话日志凭据泄露检测',
  src: 'builtin',
  runner: (sessionFile) => run(sessionFile),
};

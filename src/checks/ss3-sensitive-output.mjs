/**
 * SS3: Sensitive Output — 插件输出敏感数据检测
 *
 * 扫描会话日志中工具输出的敏感数据：
 * - 大量文件内容泄露
 * - 环境变量输出
 * - 配置文件内容
 *
 * Severity: LOW
 * Phase: POST_INSTALL
 */

import { existsSync, createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail } from '../protocol/check.mjs';

const SENSITIVE_OUTPUT_PATTERNS = [
  { name: 'env dump', regex: /(?:process\.env|ENV|env)\s*[=:]\s*\{[^}]{50,}/gi, severity: 'medium' },
  { name: 'config dump', regex: /(?:config|settings|credentials)\s*[=:]\s*\{[^}]{100,}/gi, severity: 'medium' },
  { name: 'large file content', regex: /(?:readFileSync|cat\s+)\S+[\s\S]{500,}/gi, severity: 'low' },
];

function extractToolOutputs(line) {
  try {
    const event = JSON.parse(line);
    if (event.type !== 'tool/result') return [];
    const data = event.data || {};
    const output = data.output || data.result || data.text || '';
    return [typeof output === 'string' ? output : JSON.stringify(output)];
  } catch { return []; }
}

export async function run(sessionFile) {
  const id = 'SS3';
  if (!sessionFile || !existsSync(sessionFile)) return pass(id, Severity.LOW, '无会话文件，跳过敏感输出检测');
  if (sessionFile.endsWith('.zstd')) return pass(id, Severity.LOW, 'zstd 文件需先解压');

  const findings = [];
  let lineCount = 0;
  const rl = createInterface({ input: createReadStream(sessionFile, { encoding: 'utf8' }), crlfDelay: Infinity });

  for await (const line of rl) {
    lineCount++;
    if (!line.trim()) continue;
    const outputs = extractToolOutputs(line);
    for (const output of outputs) {
      for (const pattern of SENSITIVE_OUTPUT_PATTERNS) {
        for (const match of output.matchAll(new RegExp(pattern.regex.source, 'g'))) {
          findings.push({ type: pattern.name, severity: pattern.severity, line: lineCount, snippet: match[0].slice(0, 60) });
        }
      }
    }
  }

  if (findings.length === 0) return pass(id, Severity.LOW, `扫描 ${lineCount} 行，未检测到敏感输出`);

  const details = findings.slice(0, 10).map(f => `行${f.line} — ${f.type}: ${f.snippet}`).join('\n');
  return fail(id, Severity.LOW, `检测到 ${findings.length} 个敏感输出模式：\n${details}`, '检查工具输出是否包含不必要的敏感信息');
}

export const ss3Check = { id: 'SS3', name: 'sensitive-output', severity: Severity.LOW, phase: CheckPhase.POST_INSTALL, description: '插件输出敏感数据检测', src: 'builtin', runner: (f) => run(f) };

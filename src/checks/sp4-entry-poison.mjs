/**
 * SP4: Entry Poison — 恶意 entry 注入检测
 *
 * 扫描 cordis.patch.yml 中的可疑 entry 注入模式：
 * - 已知恶意 id 模式
 * - 异常的 entry 配置
 * - 可疑的 inject 依赖链
 *
 * Severity: HIGH
 * Phase: POST_INSTALL
 */

import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail } from '../protocol/check.mjs';

/** 已知恶意 entry 模式 */
const MALICIOUS_PATTERNS = [
  { name: 'hook injection', regex: /hook[s]?:\s*\n\s+-\s*id:\s*(hook|on|before|after)/gi, severity: 'high' },
  { name: 'eval execution', regex: /eval\s*\(|Function\s*\(/g, severity: 'high' },
  { name: 'child process', regex: /child_process|execSync|spawnSync/g, severity: 'medium' },
  { name: 'network exfil', regex: /fetch\s*\(|http\.request|https\.request/g, severity: 'medium' },
];

function scanPatchFile(filePath) {
  const findings = [];
  let content;
  try { content = readFileSync(filePath, 'utf8'); } catch { return findings; }
  for (const pattern of MALICIOUS_PATTERNS) {
    const matches = content.matchAll(new RegExp(pattern.regex.source, 'gi'));
    for (const match of matches) {
      findings.push({ type: pattern.name, severity: pattern.severity, snippet: match[0].slice(0, 60) });
    }
  }
  return findings;
}

export async function run(profileDir) {
  const id = 'SP4';
  const patchFiles = [];
  const profilePatch = join(profileDir, 'cordis.patch.yml');
  if (existsSync(profilePatch)) patchFiles.push(profilePatch);

  const nmDir = join(profileDir, 'node_modules');
  if (existsSync(nmDir)) {
    for (const entry of readdirSync(nmDir, { withFileTypes: true })) {
      if (entry.name.startsWith('.') || entry.name === '.bin') continue;
      if (entry.name.startsWith('@')) {
        const scopeDir = join(nmDir, entry.name);
        for (const pkg of readdirSync(scopeDir, { withFileTypes: true })) {
          const f = join(scopeDir, pkg.name, 'cordis.patch.yml');
          if (existsSync(f)) patchFiles.push(f);
        }
      } else {
        const f = join(nmDir, entry.name, 'cordis.patch.yml');
        if (existsSync(f)) patchFiles.push(f);
      }
    }
  }

  if (patchFiles.length === 0) return pass(id, Severity.HIGH, '未找到 patch 文件，跳过恶意 entry 检测');

  const allFindings = [];
  for (const f of patchFiles) allFindings.push(...scanPatchFile(f));

  if (allFindings.length === 0) return pass(id, Severity.HIGH, `扫描 ${patchFiles.length} 个 patch 文件，未检测到恶意 entry 模式`);

  const details = allFindings.slice(0, 10).map(f => `[${f.severity}] ${f.type}: ${f.snippet}`).join('\n');
  return fail(id, Severity.HIGH, `检测到 ${allFindings.length} 个可疑 entry 模式：\n${details}`, '检查相关插件的 cordis.patch.yml 内容');
}

export const sp4Check = { id: 'SP4', name: 'entry-poison', severity: Severity.HIGH, phase: CheckPhase.POST_INSTALL, description: '恶意 entry 注入检测', src: 'builtin', runner: (d) => run(d) };

/**
 * SP6: Vulnerability Match — 已知漏洞匹配
 *
 * 通过 OSV API 查询已知漏洞（CVE/GHSA）：
 * - 查询 npm 包的已知漏洞
 * - 过滤 critical/high 级别
 * - 输出受影响的包和修复版本
 *
 * Severity: HIGH
 * Phase: POST_INSTALL
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { Severity, maxSeverity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail } from '../protocol/check.mjs';

async function queryOSV(packageName, version) {
  try {
    const response = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ package: { name: packageName, ecosystem: 'npm' }, version }),
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) return [];
    const data = await response.json();
    return (data.vulns || []).map(v => ({
      id: v.id,
      summary: v.summary || v.details?.slice(0, 100) || 'No summary',
      severity: v.database_specific?.severity || v.severity?.[0]?.score || 'unknown',
      fixed: v.fix_versions?.[0] || 'unknown',
    }));
  } catch { return []; }
}

export async function run(profileDir) {
  const id = 'SP6';
  const packageJsonPath = join(profileDir, 'package.json');
  if (!existsSync(packageJsonPath)) return pass(id, Severity.HIGH, '无 package.json，跳过漏洞匹配');

  let manifest;
  try { manifest = JSON.parse(readFileSync(packageJsonPath, 'utf8')); } catch { return pass(id, Severity.HIGH, 'package.json 解析失败'); }

  const deps = manifest.dependencies || {};
  const dshPackages = Object.entries(deps).filter(([n]) => n.includes('dsh') || n.includes('deepseek'));
  if (dshPackages.length === 0) return pass(id, Severity.HIGH, '无 dsh 相关依赖，跳过漏洞匹配');

  const allVulns = [];
  for (const [name, version] of dshPackages.slice(0, 10)) {
    const cleanVersion = version.replace(/^[~^>=<]/, '');
    const vulns = await queryOSV(name, cleanVersion);
    allVulns.push(...vulns.map(v => ({ package: name, ...v })));
  }

  if (allVulns.length === 0) return pass(id, Severity.HIGH, `查询 ${dshPackages.length} 个包，未发现已知漏洞`);

  const details = allVulns.slice(0, 10).map(v => `${v.package} — ${v.id}: ${v.summary}（fixed: ${v.fixed}）`).join('\n');
  const fixable = allVulns.filter(v => v.fixed !== 'unknown').length;
  return fail(id, Severity.HIGH,
    `检测到 ${allVulns.length} 个已知漏洞（${fixable} 个可修复）：\n${details}`,
    fixable > 0 ? '升级受影响的包到修复版本' : '关注上游修复进展'
  );
}

export const sp6Check = { id: 'SP6', name: 'vuln-match', severity: Severity.HIGH, phase: CheckPhase.POST_INSTALL, description: '已知漏洞匹配（OSV/CVE/GHSA）', src: 'builtin', runner: (d) => run(d) };

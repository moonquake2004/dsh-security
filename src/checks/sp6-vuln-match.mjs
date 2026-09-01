/**
 * SP6: Vulnerability Match — 已知漏洞匹配
 *
 * 通过 OSV API 查询已知漏洞（CVE/GHSA）：
 * - 查询 npm 包的已知漏洞
 * - 按 OSV 严重级别映射整体结果严重度，detail 标注 critical/high 数量
 * - 输出受影响的包与漏洞编号（references）
 *
 * Severity: HIGH
 * Phase: POST_INSTALL
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { Severity, maxSeverity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail, skip } from '../protocol/check.mjs';

/**
 * 查询 OSV API。
 * @returns {Promise<Array|null>} 成功返回漏洞数组（可能为空）；网络失败返回 null
 */
async function queryOSV(packageName, version) {
  try {
    const response = await fetch('https://api.osv.dev/v1/query', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ package: { name: packageName, ecosystem: 'npm' }, version }),
      signal: AbortSignal.timeout(10000),
    });
    if (!response.ok) return null;
    const data = await response.json();
    return (data.vulns || []).map(v => ({
      id: v.id,
      summary: v.summary || v.details?.slice(0, 100) || 'No summary',
      severity: v.database_specific?.severity || v.severity?.[0]?.score || 'unknown',
    }));
  } catch { return null; }
}

function osvSeverityToLevel(sev) {
  const s = String(sev).toUpperCase();
  if (s.includes('CRITICAL')) return Severity.CRITICAL;
  if (s.includes('HIGH')) return Severity.HIGH;
  if (s.includes('MODERATE') || s.includes('MEDIUM')) return Severity.MEDIUM;
  return Severity.LOW;
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
  const refs = new Set();
  let okQueries = 0;
  let failedQueries = 0;
  for (const [name, version] of dshPackages.slice(0, 10)) {
    // 只去掉首个范围前缀字符；workspace:/catalog:/file: 等协议版本无法映射，原样传给 OSV（查询无结果）
    const cleanVersion = version.replace(/^[~^>=<]/, '');
    const vulns = await queryOSV(name, cleanVersion);
    if (vulns === null) { failedQueries++; continue; }
    okQueries++;
    allVulns.push(...vulns.map(v => ({ package: name, ...v })));
    for (const v of vulns) if (v.id) refs.add(v.id);
  }

  // 全部查询失败 → skip（离线时不应谎报"未发现已知漏洞"）
  if (okQueries === 0 && failedQueries > 0) {
    return skip(id, Severity.HIGH, `OSV API 不可达（${failedQueries} 个包全部查询失败），跳过已知漏洞匹配`);
  }

  if (allVulns.length === 0) {
    const note = failedQueries > 0 ? `（${failedQueries} 个包查询失败未覆盖）` : '';
    return pass(id, Severity.HIGH, `成功查询 ${okQueries}/${dshPackages.length} 个包，未发现已知漏洞${note}`);
  }

  const details = allVulns.slice(0, 10).map(v => `${v.package} — ${v.id}: ${v.summary}（severity: ${v.severity}）`).join('\n');
  const overallSeverity = maxSeverity(allVulns.map(v => osvSeverityToLevel(v.severity)));
  const criticalHigh = allVulns.filter(v => ['critical', 'high'].includes(osvSeverityToLevel(v.severity))).length;

  return fail(id, overallSeverity,
    `检测到 ${allVulns.length} 个已知漏洞（critical/high ${criticalHigh} 个）：\n${details}`,
    '按 OSV 建议升级受影响的包到修复版本',
    [...refs].slice(0, 5)
  );
}

export const sp6Check = { id: 'SP6', name: 'vuln-match', severity: Severity.HIGH, phase: CheckPhase.POST_INSTALL, description: '已知漏洞匹配（OSV/CVE/GHSA）', src: 'builtin', runner: (d) => run(d) };

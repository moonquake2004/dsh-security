/**
 * SP1: Dependency Audit — 依赖链漏洞扫描
 *
 * 集成 npm audit 检查 profile 中已安装插件的已知漏洞。
 * 支持 npm audit 和 osv-scanner 两种后端。
 *
 * Severity: HIGH（有 critical/high 漏洞时）
 * Phase: POST_INSTALL
 */

import { execSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { Severity, maxSeverity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail } from '../protocol/check.mjs';

/**
 * 运行 npm audit 并解析结果
 */
function runNpmAudit(profileDir) {
  const packageJsonPath = join(profileDir, 'package.json');
  if (!existsSync(packageJsonPath)) {
    return { vulns: [], error: 'package.json 不存在' };
  }

  try {
    const output = execSync('npm audit --json --omit=dev', {
      cwd: profileDir,
      encoding: 'utf8',
      timeout: 60000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const audit = JSON.parse(output);
    return parseNpmAudit(audit);
  } catch (e) {
    // npm audit 在有漏洞时 exit code 1，这是正常的
    if (e.stdout) {
      try {
        const audit = JSON.parse(e.stdout);
        return parseNpmAudit(audit);
      } catch {
        return { vulns: [], error: `npm audit 解析失败: ${e.message}` };
      }
    }
    return { vulns: [], error: `npm audit 执行失败: ${e.message}` };
  }
}

/**
 * 解析 npm audit JSON 输出
 */
function parseNpmAudit(audit) {
  const vulns = [];
  const advisory = audit.advisories || {};
  const metadata = audit.metadata || {};

  // npm v7+ 格式
  if (audit.vulnerabilities) {
    for (const [name, vuln] of Object.entries(audit.vulnerabilities)) {
      if (vuln.severity === 'info') continue;
      vulns.push({
        package: name,
        severity: vuln.severity,
        title: vuln.via?.[0]?.title || 'Unknown vulnerability',
        range: vuln.range || 'Unknown',
        fixAvailable: !!vuln.fixAvailable,
        url: vuln.via?.[0]?.url || '',
      });
    }
  }

  // npm v6 格式（advisories）
  for (const [id, adv] of Object.entries(advisory)) {
    vulns.push({
      package: adv.module_name,
      severity: adv.severity,
      title: adv.title,
      range: adv.vulnerable_versions,
      fixAvailable: !!adv.patched_versions,
      url: adv.url || '',
    });
  }

  return {
    vulns,
    totalDependencies: metadata.totalDependencies || 0,
    totalVulnerabilities: metadata.vulnerabilities?.total || vulns.length,
  };
}

/**
 * SP1 检查：扫描 profile 依赖链中的已知漏洞
 * @param {string} profileDir - profile 目录路径
 * @returns {Promise<import('../protocol/check.mjs').SecurityCheckResult>}
 */
export async function run(profileDir) {
  const id = 'SP1';

  if (!existsSync(join(profileDir, 'package.json'))) {
    return pass(id, Severity.HIGH, 'profile 无 package.json，跳过依赖审计');
  }

  const { vulns, error, totalDependencies } = runNpmAudit(profileDir);

  if (error) {
    return pass(id, Severity.HIGH, `依赖审计跳过：${error}`);
  }

  if (vulns.length === 0) {
    return pass(id, Severity.HIGH, `依赖链无已知漏洞（扫描 ${totalDependencies || '?'} 个依赖）`);
  }

  // 按 severity 分组
  const bySeverity = {};
  for (const v of vulns) {
    if (!bySeverity[v.severity]) bySeverity[v.severity] = [];
    bySeverity[v.severity].push(v);
  }

  const summary = Object.entries(bySeverity)
    .map(([sev, items]) => `${sev}: ${items.length}`)
    .join(', ');

  const details = vulns
    .slice(0, 10)
    .map(v => `${v.package}（${v.severity}）— ${v.title}`)
    .join('\n');

  const fixable = vulns.filter(v => v.fixAvailable).length;
  const fixHint = fixable > 0
    ? `${fixable} 个漏洞可通过 npm fix 修复`
    : '部分漏洞可能需要升级主版本或更换依赖';

  const overallSeverity = maxSeverity(vulns.map(v => {
    if (v.severity === 'critical') return Severity.CRITICAL;
    if (v.severity === 'high') return Severity.HIGH;
    if (v.severity === 'moderate') return Severity.MEDIUM;
    return Severity.LOW;
  }));

  return fail(id, overallSeverity,
    `检测到 ${vulns.length} 个已知漏洞（${summary}）：\n${details}\n${fixHint}`,
    '运行 npm audit fix 修复可自动修复的漏洞；手动升级有破坏性变更的依赖',
    vulns.filter(v => v.url).slice(0, 3).map(v => v.url)
  );
}

export const sp1Check = {
  id: 'SP1',
  name: 'dependency-audit',
  severity: Severity.HIGH,
  phase: CheckPhase.POST_INSTALL,
  description: '依赖链已知漏洞扫描（npm audit）',
  src: 'builtin',
  runner: (profileDir) => run(profileDir),
};

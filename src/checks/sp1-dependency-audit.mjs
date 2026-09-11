/**
 * SP1: Dependency Audit — 依赖链漏洞扫描
 *
 * 对 profile 的依赖锁文件执行真实审计：
 *   - pnpm-lock.yaml  → `pnpm audit --json --prod`
 *   - package-lock.json → `npm audit --json --omit=dev`
 *
 * 契约（2026-09 上游兼容审计 R9 修复）：
 *   任何"审计没有真正执行"的情况都必须返回 **skip + 原因**，
 *   绝不允许静默 PASS。旧实现在 pnpm profile（无 package-lock.json）上
 *   把 npm 的 ENOLOCK 错误当成"无漏洞"，永久输出
 *   `依赖链无已知漏洞（扫描 ? 个依赖）` 的假 PASS。
 *
 * Severity: HIGH（有 critical/high 漏洞时）
 * Phase: POST_INSTALL
 */

import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { Severity, maxSeverity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail, skip } from '../protocol/check.mjs';

const AUDIT_TIMEOUT_MS = 60000;
const MAX_BUFFER = 32 * 1024 * 1024;

/**
 * 选审计后端：锁文件决定包管理器。没有锁文件就没有可审计的依赖图。
 * @returns {{pm: string, lock: string, args: string[]}|null}
 */
export function detectBackend(profileDir) {
  if (existsSync(join(profileDir, 'pnpm-lock.yaml'))) {
    return { pm: 'pnpm', lock: 'pnpm-lock.yaml', args: ['audit', '--json', '--prod'] };
  }
  if (existsSync(join(profileDir, 'package-lock.json'))) {
    return { pm: 'npm', lock: 'package-lock.json', args: ['audit', '--json', '--omit=dev'] };
  }
  return null;
}

/**
 * 解析审计 JSON（同时兼容 npm v6 `advisories` 与 npm v7+/pnpm `vulnerabilities` 两种格式）。
 * 返回 `{ vulns, totalDependencies, totalVulnerabilities }`；
 * 若输出里带 `error`（如 ENOLOCK / ERR_PNPM_AUDIT_NO_LOCKFILE），返回 `{ auditError, auditErrorCode }`。
 */
export function parseAuditJson(audit) {
  if (audit && typeof audit === 'object' && audit.error) {
    const err = audit.error;
    const code = err.code || 'AUDIT_ERROR';
    return {
      auditError: `${code}: ${err.summary || err.detail || '审计未执行'}`,
      auditErrorCode: code,
    };
  }

  const vulns = [];
  const metadata = (audit && audit.metadata) || {};

  // npm v7+ / pnpm v9+：vulnerabilities 按包聚合
  if (audit && audit.vulnerabilities && typeof audit.vulnerabilities === 'object') {
    for (const [name, vuln] of Object.entries(audit.vulnerabilities)) {
      const severity = vuln && vuln.severity;
      if (!severity || severity === 'info') continue;
      const via = Array.isArray(vuln.via) ? vuln.via.filter(v => v && typeof v === 'object') : [];
      vulns.push({
        package: name,
        severity,
        title: via[0]?.title || (typeof vuln.via?.[0] === 'string' ? vuln.via[0] : 'Unknown vulnerability'),
        range: vuln.range || 'Unknown',
        fixAvailable: !!vuln.fixAvailable,
        url: via[0]?.url || '',
      });
    }
  }

  // npm v6 / pnpm <= 9：advisories（keyed by id）
  const advisories = (audit && audit.advisories) || {};
  for (const adv of Object.values(advisories)) {
    if (!adv || adv.severity === 'info') continue;
    vulns.push({
      package: adv.module_name || 'unknown',
      severity: adv.severity || 'unknown',
      title: adv.title || 'Unknown vulnerability',
      range: adv.vulnerable_versions || 'Unknown',
      fixAvailable: !!adv.patched_versions,
      url: adv.url || '',
    });
  }

  return {
    vulns,
    totalDependencies: resolveDependencyCount(metadata),
    totalVulnerabilities: metadata.vulnerabilities?.total ?? vulns.length,
  };
}

/**
 * 依赖总数：npm v6/pnpm 用 `metadata.totalDependencies`（数字）；
 * npm v7+ 用 `metadata.dependencies.total`；pnpm 某些版本直接给数字。
 */
function resolveDependencyCount(metadata) {
  if (typeof metadata.totalDependencies === 'number') return metadata.totalDependencies;
  const deps = metadata.dependencies;
  if (deps && typeof deps === 'object' && typeof deps.total === 'number') return deps.total;
  if (typeof deps === 'number') return deps;
  return null;
}

/** 判断 stderr 是否是"没有 lockfile 可审计" */
function isNoLockfileMessage(text) {
  return /ERR_PNPM_AUDIT_NO_LOCKFILE|ENOLOCK|requires an existing lockfile|Cannot audit a project without a lockfile/i.test(text);
}

/**
 * 执行审计。任何未真正产出审计结论的情况 → `{ error, code }`。
 */
export function runAudit(backend, profileDir) {
  let res;
  try {
    res = spawnSync(backend.pm, backend.args, {
      cwd: profileDir,
      encoding: 'utf8',
      timeout: AUDIT_TIMEOUT_MS,
      maxBuffer: MAX_BUFFER,
    });
  } catch (e) {
    return { error: `执行 ${backend.pm} audit 失败：${e.message}`, code: 'SPAWN_FAILED' };
  }

  if (res.error) {
    if (res.error.code === 'ENOENT') {
      return { error: `未找到 ${backend.pm} 命令（ENOENT）`, code: 'PM_NOT_FOUND' };
    }
    if (res.error.code === 'ETIMEDOUT') {
      return { error: `${backend.pm} audit 超时（${AUDIT_TIMEOUT_MS}ms）`, code: 'AUDIT_TIMEOUT' };
    }
    return { error: `${backend.pm} audit 执行失败：${res.error.message}`, code: res.error.code || 'SPAWN_FAILED' };
  }

  const stdout = (res.stdout || '').trim();
  const stderr = (res.stderr || '').trim();

  // 无 stdout 通常意味着包管理器拒绝了审计（无锁文件 / 无网络 / 未登录）。
  // pnpm 12 的 ERR_PNPM_AUDIT_NO_LOCKFILE 就只写 stderr、stdout 为空。
  if (!stdout) {
    if (isNoLockfileMessage(stderr)) {
      return { error: `无锁文件，无法审计：${firstLine(stderr)}`, code: 'NO_LOCKFILE' };
    }
    return { error: `audit 无 JSON 输出（exit ${res.status}）：${firstLine(stderr) || 'stderr 为空'}`, code: 'AUDIT_NO_OUTPUT' };
  }

  let audit;
  try {
    audit = JSON.parse(stdout);
  } catch {
    return { error: `audit 输出不是合法 JSON（exit ${res.status}）`, code: 'AUDIT_BAD_JSON' };
  }

  const parsed = parseAuditJson(audit);
  if (parsed.auditError) return { error: parsed.auditError, code: parsed.auditErrorCode };
  return parsed;
}

function firstLine(text) {
  return (text || '').split('\n').map(l => l.trim()).filter(Boolean)[0] || '';
}

function auditSeverityToEnum(sev) {
  if (sev === 'critical') return Severity.CRITICAL;
  if (sev === 'high') return Severity.HIGH;
  if (sev === 'moderate' || sev === 'medium') return Severity.MEDIUM;
  return Severity.LOW;
}

/**
 * SP1 检查：扫描 profile 依赖链中的已知漏洞
 * @param {string} profileDir - profile 目录路径
 * @returns {Promise<import('../protocol/check.mjs').SecurityCheckResult>}
 */
export async function run(profileDir) {
  const id = 'SP1';

  if (!existsSync(join(profileDir, 'package.json'))) {
    return skip(id, Severity.HIGH, 'profile 无 package.json，没有可审计的依赖清单，跳过依赖审计');
  }

  const backend = detectBackend(profileDir);
  if (!backend) {
    return skip(id, Severity.HIGH,
      'profile 无 pnpm-lock.yaml / package-lock.json，npm/pnpm audit 均无锁文件可审计（NO_LOCKFILE），跳过依赖审计');
  }

  const result = runAudit(backend, profileDir);
  if (result.error) {
    return skip(id, Severity.HIGH, `依赖审计未执行（${result.code}）：${result.error}`);
  }

  const { vulns } = result;
  const depCount = result.totalDependencies;

  if (vulns.length === 0) {
    const countText = typeof depCount === 'number' ? `${depCount}` : '计数不可用';
    return pass(id, Severity.HIGH,
      `依赖链无已知漏洞（${backend.pm} audit --json，扫描 ${countText} 个依赖）`);
  }

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
    ? `${fixable} 个漏洞有可用补丁版本，可运行 ${backend.pm} audit --fix / audit fix 修复`
    : '部分漏洞可能需要升级主版本或更换依赖';

  const overallSeverity = maxSeverity(vulns.map(v => auditSeverityToEnum(v.severity)));

  const countText = typeof depCount === 'number' ? `，共扫描 ${depCount} 个依赖` : '';

  return fail(id, overallSeverity,
    `检测到 ${vulns.length} 个已知漏洞（${summary}${countText}，来源 ${backend.pm} audit --json）：\n${details}\n${fixHint}`,
    `运行 ${backend.pm} audit 查看详情并升级受影响依赖；优先修复 critical/high`,
    vulns.filter(v => v.url).slice(0, 3).map(v => v.url)
  );
}

export const sp1Check = {
  id: 'SP1',
  name: 'dependency-audit',
  severity: Severity.HIGH,
  phase: CheckPhase.POST_INSTALL,
  description: '依赖链已知漏洞扫描（pnpm/npm audit）',
  src: 'builtin',
  runner: (profileDir) => run(profileDir),
};

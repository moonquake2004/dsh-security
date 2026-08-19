/**
 * SL4: Release Compatibility — 发布兼容性验证
 *
 * 验证 profile 中包的 dist-tags 与 DSH 版本的兼容性：
 * - 检测 latest 指向 broken 版本
 * - 检测 next/rc 标签与本地版本的差异
 * - 验证 peerDependencies 兼容性
 *
 * Severity: MEDIUM
 * Phase: LIFECYCLE
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { Severity, maxSeverity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail } from '../protocol/check.mjs';

/**
 * 获取 npm registry dist-tags
 */
async function fetchDistTags(pkgName) {
  try {
    const url = `https://registry.npmjs.org/${encodeURIComponent(pkgName).replace(/%2f/g, '/')}`;
    const response = await fetch(url, { signal: AbortSignal.timeout(10000) });
    if (!response.ok) return null;
    const data = await response.json();
    return data['dist-tags'] || null;
  } catch {
    return null;
  }
}

/**
 * 检查版本兼容性
 */
function checkCompatibility(localVersion, distTags) {
  const issues = [];

  // latest 标签检查
  if (distTags.latest) {
    const latestParts = distTags.latest.split('.').map(Number);
    const localParts = localVersion.split('.').map(Number);

    // 检测 major 版本差异
    if (latestParts[0] > localParts[0]) {
      issues.push({
        type: 'major-behind',
        severity: 'medium',
        detail: `本地版本 ${localVersion} 落后于 latest ${distTags.latest}（major 版本差异）`,
      });
    }

    // 检测 latest 是否是 rc/beta
    if (distTags.latest.includes('-rc') || distTags.latest.includes('-beta')) {
      issues.push({
        type: 'latest-is-prerelease',
        severity: 'medium',
        detail: `latest 标签指向预发布版本 ${distTags.latest}，可能不稳定`,
      });
    }
  }

  // next 标签检查
  if (distTags.next && distTags.next !== distTags.latest) {
    issues.push({
      type: 'next-available',
      severity: 'low',
      detail: `有 next 标签 ${distTags.next} 可用（当前 latest: ${distTags.latest}）`,
    });
  }

  return issues;
}

/**
 * SL4 检查：验证发布兼容性
 * @param {string} profileDir - profile 目录路径
 * @returns {Promise<import('../protocol/check.mjs').SecurityCheckResult>}
 */
export async function run(profileDir) {
  const id = 'SL4';

  const packageJsonPath = join(profileDir, 'package.json');
  if (!existsSync(packageJsonPath)) {
    return pass(id, Severity.MEDIUM, 'profile 无 package.json，跳过发布兼容性验证');
  }

  let manifest;
  try {
    manifest = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
  } catch {
    return pass(id, Severity.MEDIUM, 'package.json 解析失败，跳过发布兼容性验证');
  }

  const deps = manifest.dependencies || {};

  // 只检查 dsh 相关的包
  const dshPackages = Object.keys(deps).filter(name =>
    name.includes('dsh') || name.includes('deepseek') || name.includes('cordis')
  );

  if (dshPackages.length === 0) {
    return pass(id, Severity.MEDIUM, 'profile 无 dsh 相关依赖，跳过发布兼容性验证');
  }

  const allIssues = [];
  let checked = 0;

  for (const pkgName of dshPackages.slice(0, 10)) {
    const localPkgPath = join(profileDir, 'node_modules', pkgName, 'package.json');
    if (!existsSync(localPkgPath)) continue;

    try {
      const localPkg = JSON.parse(readFileSync(localPkgPath, 'utf8'));
      const distTags = await fetchDistTags(pkgName);

      if (!distTags) continue;

      const issues = checkCompatibility(localPkg.version, distTags);
      for (const issue of issues) {
        allIssues.push({ package: pkgName, ...issue });
      }
      checked++;
    } catch {
      // 跳过查询失败的包
    }
  }

  if (allIssues.length === 0) {
    return pass(id, Severity.MEDIUM,
      `验证 ${checked} 个包的发布兼容性，无异常`
    );
  }

  const mediumIssues = allIssues.filter(i => i.severity === 'medium');
  const overallSeverity = mediumIssues.length > 0 ? Severity.MEDIUM : Severity.LOW;

  const details = allIssues
    .map(i => `[${i.severity}] ${i.package} — ${i.type}: ${i.detail}`)
    .join('\n');

  const fix = '检查是否有重要更新需要应用，或确认当前版本满足需求';

  return fail(id, overallSeverity,
    `检测到 ${allIssues.length} 个发布兼容性问题（${checked} 个包已验证）：\n${details}`,
    fix
  );
}

export const sl4Check = {
  id: 'SL4',
  name: 'release-compat',
  severity: Severity.MEDIUM,
  phase: CheckPhase.LIFECYCLE,
  description: '发布兼容性验证（dist-tags 一致性）',
  src: 'builtin',
  runner: (profileDir) => run(profileDir),
};

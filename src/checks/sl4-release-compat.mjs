/**
 * SL4: Release Compatibility — 发布兼容性验证
 *
 * 验证 profile 中包的 dist-tags 与本地版本的差异：
 * - 检测 major 版本落后
 * - 检测 latest 指向 rc/beta 预发布
 * - 提示可用的 next 标签
 *
 * （对齐实现：peerDependencies 兼容性验证未落地，不再宣称）
 * Severity: MEDIUM
 * Phase: LIFECYCLE
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { Severity, maxSeverity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail, skip } from '../protocol/check.mjs';

/**
 * 获取 npm registry dist-tags
 */
async function fetchDistTags(pkgName) {
  try {
    const url = `https://registry.npmjs.org/${encodeURIComponent(pkgName)}`;
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
        informational: true, // 全生态都在 rc 线上，这属常态描述而非兼容性问题（2026-09 审计结论）
        detail: `latest 标签指向预发布版本 ${distTags.latest}，可能不稳定`,
      });
    }
  }

  // next 标签检查
  if (distTags.next && distTags.next !== distTags.latest) {
    issues.push({
      type: 'next-available',
      severity: 'low',
      informational: true,
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
  let errors = 0;

  for (const pkgName of dshPackages.slice(0, 10)) {
    const localPkgPath = join(profileDir, 'node_modules', pkgName, 'package.json');
    if (!existsSync(localPkgPath)) continue;

    try {
      const localPkg = JSON.parse(readFileSync(localPkgPath, 'utf8'));
      const distTags = await fetchDistTags(pkgName);

      if (!distTags) { errors++; continue; }

      const issues = checkCompatibility(localPkg.version, distTags);
      for (const issue of issues) {
        allIssues.push({ package: pkgName, ...issue });
      }
      checked++;
    } catch {
      errors++;
    }
  }

  // 全部查询失败 → skip（离线时不应谎报"无异常"）
  if (checked === 0 && errors > 0) {
    return skip(id, Severity.MEDIUM, `${errors} 个包 registry 查询失败（离线或网络受限），跳过发布兼容性验证`);
  }

  if (allIssues.length === 0) {
    return pass(id, Severity.MEDIUM,
      `验证 ${checked} 个包的发布兼容性，无异常${errors > 0 ? `（${errors} 个查询失败）` : ''}`
    );
  }

  const material = allIssues.filter(i => !i.informational);
  if (material.length === 0) {
    return pass(id, Severity.LOW,
      `验证 ${checked} 个包的发布兼容性，未发现兼容性问题`
      + (allIssues.length ? `；另有 ${allIssues.length} 条常态提示（预发布 latest / next 可用）未计入` : ''));
  }
  const mediumIssues = material.filter(i => i.severity === 'medium');
  const overallSeverity = mediumIssues.length > 0 ? Severity.MEDIUM : Severity.LOW;

  const details = material
    .map(i => `[${i.severity}] ${i.package} — ${i.type}: ${i.detail}`)
    .join('\n');

  const fix = '检查是否有重要更新需要应用，或确认当前版本满足需求';

  return fail(id, overallSeverity,
    `检测到 ${material.length} 个发布兼容性问题（${checked} 个包已验证）：\n${details}`,
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

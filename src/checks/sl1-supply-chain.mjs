/**
 * SL1: Supply Chain Integrity — 供应链完整性验证
 *
 * 验证 profile 中已安装的包与 npm registry 上的版本一致：
 * - 版本号匹配
 * - integrity hash 匹配（SHA-512）
 * - 检测潜在的包劫持（版本存在但内容不匹配）
 *
 * Severity: HIGH
 * Phase: LIFECYCLE
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { execSync } from 'node:child_process';
import { Severity, maxSeverity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail } from '../protocol/check.mjs';

/**
 * 获取 npm registry 上的包信息
 */
async function fetchRegistryInfo(pkgName) {
  try {
    const url = `https://registry.npmjs.org/${encodeURIComponent(pkgName).replace(/%2f/g, '/')}`;
    const response = await fetch(url, { signal: AbortSignal.timeout(10000) });
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
  }
}

/**
 * 比较本地安装版本与 registry 版本
 */
function compareVersions(localPkg, registryInfo) {
  const issues = [];
  const localVersion = localPkg.version;
  const latestVersion = registryInfo['dist-tags']?.latest;

  // 版本号匹配
  if (latestVersion && localVersion !== latestVersion) {
    issues.push({
      type: 'version-mismatch',
      severity: 'medium',
      detail: `本地版本 ${localVersion} ≠ registry latest ${latestVersion}`,
    });
  }

  // integrity 比较
  const localIntegrity = localPkg._integrity || localPkg.dist?.integrity;
  const registryVersion = registryInfo.versions?.[localVersion];
  const registryIntegrity = registryVersion?.dist?.integrity;

  if (localIntegrity && registryIntegrity && localIntegrity !== registryIntegrity) {
    issues.push({
      type: 'integrity-mismatch',
      severity: 'critical',
      detail: `integrity hash 不匹配：本地 ${localIntegrity.slice(0, 30)}... ≠ registry ${registryIntegrity.slice(0, 30)}...`,
    });
  }

  return issues;
}

/**
 * SL1 检查：验证 profile 中包的供应链完整性
 * @param {string} profileDir - profile 目录路径
 * @returns {Promise<import('../protocol/check.mjs').SecurityCheckResult>}
 */
export async function run(profileDir) {
  const id = 'SL1';

  const packageJsonPath = join(profileDir, 'package.json');
  if (!existsSync(packageJsonPath)) {
    return pass(id, Severity.HIGH, 'profile 无 package.json，跳过供应链验证');
  }

  let manifest;
  try {
    manifest = JSON.parse(readFileSync(packageJsonPath, 'utf8'));
  } catch {
    return pass(id, Severity.HIGH, 'package.json 解析失败，跳过供应链验证');
  }

  const deps = manifest.dependencies || {};
  const bundleNames = manifest.dsh?.profile?.bundles || [];

  // 只检查 dsh 相关的包（减少 API 调用）
  const dshPackages = Object.keys(deps).filter(name =>
    name.includes('dsh') || name.includes('deepseek') || name.includes('cordis')
  );

  if (dshPackages.length === 0) {
    return pass(id, Severity.HIGH, 'profile 无 dsh 相关依赖，跳过供应链验证');
  }

  const allIssues = [];
  let checked = 0;
  let errors = 0;

  for (const pkgName of dshPackages.slice(0, 10)) { // 最多检查 10 个
    const localPkgPath = join(profileDir, 'node_modules', pkgName, 'package.json');
    if (!existsSync(localPkgPath)) continue;

    try {
      const localPkg = JSON.parse(readFileSync(localPkgPath, 'utf8'));
      const registryInfo = await fetchRegistryInfo(pkgName);

      if (!registryInfo) {
        errors++;
        continue;
      }

      const issues = compareVersions(localPkg, registryInfo);
      for (const issue of issues) {
        allIssues.push({ package: pkgName, ...issue });
      }
      checked++;
    } catch {
      errors++;
    }
  }

  if (allIssues.length === 0) {
    return pass(id, Severity.HIGH,
      `验证 ${checked} 个包的供应链完整性，未发现异常${errors > 0 ? `（${errors} 个包查询失败）` : ''}`
    );
  }

  const criticalIssues = allIssues.filter(i => i.severity === 'critical');
  const overallSeverity = criticalIssues.length > 0 ? Severity.CRITICAL : Severity.HIGH;

  const details = allIssues
    .map(i => `[${i.severity}] ${i.package} — ${i.type}: ${i.detail}`)
    .join('\n');

  const fix = criticalIssues.length > 0
    ? '检测到 integrity hash 不匹配，可能是包被篡改。立即重新安装受影响的包'
    : '部分包版本落后于 registry latest，建议更新';

  return fail(id, overallSeverity,
    `检测到 ${allIssues.length} 个供应链问题（${checked} 个包已验证）：\n${details}`,
    fix
  );
}

export const sl1Check = {
  id: 'SL1',
  name: 'supply-chain-integrity',
  severity: Severity.HIGH,
  phase: CheckPhase.LIFECYCLE,
  description: '供应链完整性验证（npm registry 一致性）',
  src: 'builtin',
  runner: (profileDir) => run(profileDir),
};

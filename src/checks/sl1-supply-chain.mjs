/**
 * SL1: Supply Chain Integrity — 供应链完整性验证
 *
 * 验证 profile 中已安装的包与 npm registry 上的版本一致：
 * - 版本号匹配（本地 vs dist-tags.latest）
 * - integrity hash 匹配：以 pnpm-lock.yaml 中锁定的 sha512 为本地基准，
 *   与 registry versions[localVersion].dist.integrity 比对，检测发布被篡改/覆盖。
 *   （复审修复：安装产物 package.json 本身不含 integrity 字段，旧实现该分支永不生效）
 *
 * 网络不可达时返回 skip（不再静默当作通过）。
 *
 * Severity: HIGH
 * Phase: LIFECYCLE
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { Severity, maxSeverity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail, skip } from '../protocol/check.mjs';

/**
 * 获取 npm registry 上的包信息
 */
async function fetchRegistryInfo(pkgName) {
  try {
    // encodeURIComponent 对 scoped 名产生 %2F，npm registry 接受该规范形式
    const url = `https://registry.npmjs.org/${encodeURIComponent(pkgName)}`;
    const response = await fetch(url, { signal: AbortSignal.timeout(10000) });
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
  }
}

/**
 * 从 pnpm-lock.yaml 提取 <name>@<version> 锁定的 integrity（sha512-...）。
 * 零依赖实现：只做定位 key 行 + 向后小窗口找 resolution.integrity。
 */
export function extractLockIntegrity(lockText, pkgName, version) {
  if (!lockText || !pkgName || !version) return null;
  const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const keyRe = new RegExp(`^\\s{2}['"]?${esc(pkgName)}@${esc(version)}['"]?:\\s*$`, 'm');
  const m = keyRe.exec(lockText);
  if (!m) return null;
  const window = lockText.slice(m.index, m.index + 500);
  const im = /integrity:\s*(sha[0-9]+-[A-Za-z0-9+/=]+)/.exec(window);
  return im ? im[1] : null;
}

/**
 * 比较本地安装版本与 registry 版本
 */
export function compareVersions(localPkg, registryInfo, localLockIntegrity = null) {
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

  // integrity 比较：优先用 pnpm-lock.yaml 锁定值；registry 同版本被篡改/覆盖时会不一致
  const registryVersion = registryInfo.versions?.[localVersion];
  const registryIntegrity = registryVersion?.dist?.integrity;
  const localIntegrity = localLockIntegrity || localPkg._integrity || null;

  if (localIntegrity && registryIntegrity && localIntegrity !== registryIntegrity) {
    issues.push({
      type: 'integrity-mismatch',
      severity: 'critical',
      detail: `integrity hash 不匹配：本地 ${String(localIntegrity).slice(0, 30)}... ≠ registry ${String(registryIntegrity).slice(0, 30)}...`,
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

  // 只检查 dsh 相关的包（减少 API 调用）
  const dshPackages = Object.keys(deps).filter(name =>
    name.includes('dsh') || name.includes('deepseek') || name.includes('cordis')
  );

  if (dshPackages.length === 0) {
    return pass(id, Severity.HIGH, 'profile 无 dsh 相关依赖，跳过供应链验证');
  }

  const lockPath = join(profileDir, 'pnpm-lock.yaml');
  let lockText = null;
  try {
    if (existsSync(lockPath)) lockText = readFileSync(lockPath, 'utf8');
  } catch { lockText = null; }

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

      const lockIntegrity = lockText ? extractLockIntegrity(lockText, pkgName, localPkg.version) : null;
      const issues = compareVersions(localPkg, registryInfo, lockIntegrity);
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
    return skip(id, Severity.HIGH, `${errors} 个包 registry 查询失败（离线或网络受限），跳过供应链验证`);
  }

  if (allIssues.length === 0) {
    return pass(id, Severity.HIGH,
      `验证 ${checked} 个包的供应链完整性，未发现异常${errors > 0 ? `（${errors} 个包查询失败）` : ''}`
    );
  }

  const criticalIssues = allIssues.filter(i => i.severity === 'critical');
  const overallSeverity = criticalIssues.length > 0 ? Severity.CRITICAL : maxSeverity(allIssues.map(i => i.severity === 'critical' ? Severity.CRITICAL : i.severity === 'medium' ? Severity.MEDIUM : Severity.LOW));

  const details = allIssues
    .map(i => `[${i.severity}] ${i.package} — ${i.type}: ${i.detail}`)
    .join('\n');

  const fix = criticalIssues.length > 0
    ? '检测到 integrity hash 不匹配，可能是包被篡改。立即重新安装受影响的包'
    : '部分包版本落后于 registry latest，建议更新';

  return fail(id, overallSeverity,
    `检测到 ${allIssues.length} 个供应链问题（${checked} 个包已验证${errors > 0 ? `，${errors} 个查询失败` : ''}）：\n${details}`,
    fix
  );
}

export const sl1Check = {
  id: 'SL1',
  name: 'supply-chain-integrity',
  severity: Severity.HIGH,
  phase: CheckPhase.LIFECYCLE,
  description: '供应链完整性验证（npm registry 一致性 + pnpm-lock integrity 比对）',
  src: 'builtin',
  runner: (profileDir) => run(profileDir),
};

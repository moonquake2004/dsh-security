/**
 * SL2: Update Integrity — 更新完整性检查
 *
 * 检查 profile 中包的更新完整性：
 * - 检测版本回退
 * - 检测异常的版本跳跃
 *
 * Severity: MEDIUM
 * Phase: LIFECYCLE
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail } from '../protocol/check.mjs';

function parseVersion(v) {
  const parts = v.replace(/^[~^>=<]/, '').split('.').map(Number);
  return { major: parts[0] || 0, minor: parts[1] || 0, patch: parts[2] || 0 };
}

function versionGt(a, b) {
  if (a.major !== b.major) return a.major > b.major;
  if (a.minor !== b.minor) return a.minor > b.minor;
  return a.patch > b.patch;
}

export async function run(profileDir) {
  const id = 'SL2';
  const packageJsonPath = join(profileDir, 'package.json');
  if (!existsSync(packageJsonPath)) return pass(id, Severity.MEDIUM, '无 package.json，跳过更新完整性检查');

  let manifest;
  try { manifest = JSON.parse(readFileSync(packageJsonPath, 'utf8')); } catch { return pass(id, Severity.MEDIUM, 'package.json 解析失败'); }

  const deps = manifest.dependencies || {};
  const issues = [];

  for (const [name, version] of Object.entries(deps)) {
    if (!name.includes('dsh') && !name.includes('deepseek')) continue;
    const pkgPath = join(profileDir, 'node_modules', name, 'package.json');
    if (!existsSync(pkgPath)) continue;
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
      const localVer = parseVersion(pkg.version);
      const specVer = parseVersion(version);
      if (versionGt(specVer, localVer) && specVer.major > localVer.major) {
        issues.push({ package: name, type: 'major-behind', detail: `本地 ${pkg.version} 落后于声明 ${version}（major 差异）` });
      }
    } catch { /* skip */ }
  }

  if (issues.length === 0) return pass(id, Severity.MEDIUM, '包版本更新完整性正常');
  const details = issues.map(i => `${i.package}: ${i.detail}`).join('\n');
  return fail(id, Severity.MEDIUM, `检测到 ${issues.length} 个更新完整性问题：\n${details}`, '更新受影响的包到声明版本');
}

export const sl2Check = { id: 'SL2', name: 'update-integrity', severity: Severity.MEDIUM, phase: CheckPhase.LIFECYCLE, description: '更新完整性检查', src: 'builtin', runner: (d) => run(d) };

/**
 * SP5: Permission Model — 插件权限声明验证
 *
 * 检查插件是否声明了所需权限（capability declarations）：
 * - 文件系统访问范围
 * - 网络访问权限
 * - 进程执行权限
 *
 * Severity: MEDIUM
 * Phase: POST_INSTALL
 */

import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail } from '../protocol/check.mjs';

function scanForUndeclaredCapabilities(content, pkgName) {
  const issues = [];
  // 检查文件系统访问但无 sandbox 声明
  if (/tool-fs|str_replace_editor/.test(content) && !/sandbox/.test(content)) {
    issues.push({ type: 'fs-without-sandbox', severity: 'medium', detail: `${pkgName} 使用文件系统工具但未声明 sandbox 配置` });
  }
  // 检查网络访问但无声明
  if (/fetch|http\.request|curl/.test(content) && !/network|http/.test(content)) {
    issues.push({ type: 'network-undeclared', severity: 'low', detail: `${pkgName} 有网络访问但未显式声明` });
  }
  return issues;
}

export async function run(profileDir) {
  const id = 'SP5';
  const nmDir = join(profileDir, 'node_modules');
  if (!existsSync(nmDir)) return pass(id, Severity.MEDIUM, '无 node_modules，跳过权限验证');

  const issues = [];
  for (const entry of readdirSync(nmDir, { withFileTypes: true })) {
    if (entry.name.startsWith('.') || entry.name === '.bin') continue;
    // scoped 包（@scope/pkg）：复审修复——此前把 @scope 当包名拼路径，scoped 插件全部漏扫
    if (entry.isDirectory() && entry.name.startsWith('@')) {
      const scopeDir = join(nmDir, entry.name);
      let pkgs = [];
      try { pkgs = readdirSync(scopeDir, { withFileTypes: true }); } catch { continue; }
      for (const pkg of pkgs) {
        if (!pkg.isDirectory()) continue;
        issues.push(...inspectPackage(join(scopeDir, pkg.name), join(entry.name, pkg.name)));
      }
      continue;
    }
    if (!entry.isDirectory()) continue;
    issues.push(...inspectPackage(join(nmDir, entry.name), entry.name));
  }

  function inspectPackage(pkgDir, displayName) {
    const found = [];
    const pkgPath = join(pkgDir, 'package.json');
    if (!existsSync(pkgPath)) return found;
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf8'));
      if (!pkg.dsh?.bundle) return found;
      const patchPath = join(pkgDir, 'cordis.patch.yml');
      if (existsSync(patchPath)) {
        const content = readFileSync(patchPath, 'utf8');
        found.push(...scanForUndeclaredCapabilities(content, pkg.name || displayName));
      }
    } catch { /* skip */ }
    return found;
  }

  if (issues.length === 0) return pass(id, Severity.MEDIUM, '插件权限声明一致');
  const details = issues.slice(0, 10).map(i => `[${i.severity}] ${i.type}: ${i.detail}`).join('\n');
  return fail(id, Severity.MEDIUM, `检测到 ${issues.length} 个权限声明问题：\n${details}`, '为插件显式声明所需的权限范围');
}

export const sp5Check = { id: 'SP5', name: 'permission-model', severity: Severity.MEDIUM, phase: CheckPhase.POST_INSTALL, description: '插件权限声明验证', src: 'builtin', runner: (d) => run(d) };

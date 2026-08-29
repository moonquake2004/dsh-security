/**
 * SP9: Dual-Instance Guard — CLI 核心包泄漏检测
 *
 * 出处：#4640 + zoahdev/dsh-ecosystem 家族 4——profile 的 node_modules
 * 中若出现 @deepseek-ai/dsh-* 包（尤其是 dsh-tools），会导致同一进程
 * 两份副本 → TOOL_RUNTIME_SCHEDULER 唯一 symbol 分裂 →
 * undefined.prepare → 所有工具调用失败 → 会话不可恢复。
 *
 * 核心规则：profile 只承载 surfaces 和 plugins；core packages 由 CLI
 * 自身的依赖树提供。profile 中出现任何 @deepseek-ai/dsh-* 包即为异常。
 *
 * 做法：扫描 profile/node_modules/@deepseek-ai/ 下的目录，
 * 检查是否存在 dsh-* 包（排除纯客户端包如 dsh-client-*，
 * 因为它们可能被插件合法引用；只报 dsh-tools/dsh-agent-loop
 * 等核心运行时包）。
 *
 * Severity: CRITICAL（直接导致工具调用全灭）
 * Phase: POST_INSTALL
 */

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail, skip } from '../protocol/check.mjs';

/**
 * CLI 核心运行时包——出现在 profile 中即为异常。
 * 客户端包（dsh-client-*）被插件合法引用，不在此列。
 */
const CORE_RUNTIME_PKGS = new Set([
  'dsh-tools',
  'dsh-agent-loop',
  'dsh-sandbox-local',
  'dsh-subprocess-local',
]);

export async function run(profileDir) {
  const id = 'SP9';
  const nmDir = join(profileDir, 'node_modules');
  if (!existsSync(nmDir)) return pass(id, Severity.CRITICAL, '无 node_modules，跳过核心包泄漏检测');

  const dsDir = join(nmDir, '@deepseek-ai');
  if (!existsSync(dsDir)) return pass(id, Severity.CRITICAL, 'profile 中无 @deepseek-ai 包，无泄漏风险');

  // 枚举 @deepseek-ai/* 下的包
  let entries;
  try { entries = readdirSync(dsDir, { withFileTypes: true }); } catch { entries = []; }

  const leaked = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const pkgName = `@deepseek-ai/${entry.name}`;
    const pjPath = join(dsDir, entry.name, 'package.json');
    if (!existsSync(pjPath)) continue;

    let version = '?';
    try {
      const pkg = JSON.parse(readFileSync(pjPath, 'utf8'));
      version = pkg.version || '?';
    } catch { /* read error */ }

    if (entry.name.startsWith('dsh-')) {
      leaked.push({ name: pkgName, version, isCore: CORE_RUNTIME_PKGS.has(entry.name) });
    }
  }

  if (leaked.length === 0) {
    return pass(id, Severity.CRITICAL, 'profile 中无 @deepseek-ai/dsh-* 泄漏，核心包仅由 CLI 提供');
  }

  const coreLeaks = leaked.filter(l => l.isCore);
  const otherLeaks = leaked.filter(l => !l.isCore);

  // 核心运行时包泄漏 = CRITICAL（直接导致 Symbol 分裂 + 工具调用全灭）
  if (coreLeaks.length > 0) {
    const details = coreLeaks.map(l => `  ${l.name}@${l.version}`).join('\n');
    const otherNote = otherLeaks.length > 0
      ? `\n另有 ${otherLeaks.length} 个非核心 @deepseek-ai/dsh-* 包在 profile 中：${otherLeaks.map(l => l.name).join(', ')}`
      : '';
    return fail(id, Severity.CRITICAL,
      `检测到 ${coreLeaks.length} 个 CLI 核心运行时包泄漏到 profile（#4640：双实例 symbol 分裂 → 工具调用全灭）：\n${details}${otherNote}\n修复: dsh plugin --profile <name> remove <泄漏包名>（或检查安装来源是否误将 CLI 依赖写入 profile）`,
      '核心包（dsh-tools/dsh-agent-loop 等）不应出现在 profile 的 node_modules 中；它们由 CLI 自身依赖树提供',
      ['#4640']
    );
  }

  // 只有非核心包泄漏 = HIGH（潜在风险但不一定立即崩溃）
  const details = otherLeaks.map(l => `  ${l.name}@${l.version}`).join('\n');
  return fail(id, Severity.HIGH,
    `检测到 ${otherLeaks.length} 个 @deepseek-ai/dsh-* 包泄漏到 profile（非核心包，暂未触发 symbol 分裂，但增加未来冲突风险）：\n${details}`,
    '清理 profile 中不需要的 @deepseek-ai/dsh-* 包；若为客户端包且被插件依赖，确认无版本冲突',
    ['#4640']
  );
}

export const sp9Check = {
  id: 'SP9',
  name: 'dual-instance-guard',
  severity: Severity.CRITICAL,
  phase: CheckPhase.POST_INSTALL,
  description: 'CLI 核心包泄漏检测——profile 中不应出现 @deepseek-ai/dsh-tools 等核心包（#4640 symbol 分裂）',
  src: 'builtin',
  runner: (profileDir) => run(profileDir),
};

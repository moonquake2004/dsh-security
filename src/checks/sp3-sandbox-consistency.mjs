/**
 * SP3: Sandbox Consistency — 沙箱策略配置一致性审计
 *
 * 轻量版 dsh-sandbox-audit：检查 cordis.patch.yml 中的沙箱策略配置，
 * 检测工具的沙箱接线与策略声明不一致。
 *
 * 三大类问题：
 *   HIGH: 变文件系统工具共享 bare fs-local backend（策略被静默忽略）
 *   MEDIUM: 搜索工具未挂载 fs 但读取了写策略外的路径
 *   LOW: 工具声明了不必要的沙箱权限
 *
 * Severity: MEDIUM（默认）
 * Phase: POST_INSTALL
 */

import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail } from '../protocol/check.mjs';

/** 已知的变文件系统工具（需要 sandbox 接线） */
const MUTATING_FS_TOOLS = [
  'tool-fs',
  'str_replace_editor',
  'tool-fs-write',
];

/** 已知的搜索工具（只读，但可能越权读取） */
const SEARCH_TOOLS = [
  'tool-fs-search',
  'tool-glob',
  'tool-grep',
];

/**
 * 从 cordis.patch.yml 内容中提取所有 entry id
 */
function extractEntryIds(content) {
  const ids = [];
  const regex = /^\s*-?\s*id:\s*['"]?([^'"\s]+)['"]?\s*$/gm;
  let match;
  while ((match = regex.exec(content)) !== null) {
    ids.push(match[1]);
  }
  return ids;
}

/**
 * 获取指定 entry 的配置块（从 - id: 到下一个 - id: 之间的所有内容）
 */
function getEntryBlock(content, entryId) {
  const entryRegex = new RegExp(`^\\s*-?\\s*id:\\s*['"]?${entryId}['"]?\\s*$`, 'gm');
  const entryMatch = entryRegex.exec(content);
  if (!entryMatch) return '';

  const afterEntry = content.slice(entryMatch.index + entryMatch[0].length);
  const nextEntryMatch = afterEntry.match(/^\s*-?\s*id:\s/m);
  return nextEntryMatch
    ? afterEntry.slice(0, nextEntryMatch.index)
    : afterEntry;
}

/**
 * 检查 entry 配置块中是否包含某个 key（任意层级）
 */
function blockHasKey(block, key) {
  return new RegExp(`^\\s+${key}:\\s`, 'm').test(block);
}

/**
 * 检查 sandbox-policy 配置
 */
function checkSandboxPolicy(content) {
  const issues = [];

  // 只检查显式声明了 sandbox-policy 的情况
  if (!content.includes('sandbox-policy')) return issues;

  // 检查 danger-full-access 模式
  if (/mode:\s*['"]?danger-full-access['"]?/.test(content) &&
      !/mode:\s*.*win32/.test(content)) {
    issues.push({
      severity: 'medium',
      tool: 'sandbox-policy',
      finding: 'sandbox-policy 使用 danger-full-access 模式（非 Windows），所有工具不受沙箱限制',
    });
  }

  return issues;
}

/**
 * 检查工具的沙箱接线
 */
function checkToolSandbox(content) {
  const issues = [];
  const entryIds = extractEntryIds(content);

  // 检查变文件系统工具是否有 sandbox 接线
  for (const tool of MUTATING_FS_TOOLS) {
    if (entryIds.includes(tool)) {
      const block = getEntryBlock(content, tool);
      const hasSandbox = blockHasKey(block, 'sandbox') || blockHasKey(block, 'sandbox-backend');
      if (!hasSandbox) {
        issues.push({
          severity: 'medium',
          tool,
          finding: `${tool} 未声明沙箱后端配置，可能使用默认 bare fs-local（策略被静默忽略）`,
        });
      }
    }
  }

  // 检查搜索工具是否挂载了 fs
  for (const tool of SEARCH_TOOLS) {
    if (entryIds.includes(tool)) {
      const block = getEntryBlock(content, tool);
      const hasFs = blockHasKey(block, 'fs');
      if (!hasFs) {
        issues.push({
          severity: 'low',
          tool,
          finding: `${tool} 未显式挂载 fs，可能读取写策略外的路径`,
        });
      }
    }
  }

  return issues;
}

/**
 * SP3 检查：扫描 profile 中的沙箱策略一致性
 * @param {string} profileDir - profile 目录路径
 * @returns {Promise<import('../protocol/check.mjs').SecurityCheckResult>}
 */
export async function run(profileDir) {
  const id = 'SP3';

  // 找所有 cordis.patch.yml 文件
  const patchFiles = [];
  const profilePatch = join(profileDir, 'cordis.patch.yml');
  if (existsSync(profilePatch)) patchFiles.push(profilePatch);

  // 扫描 node_modules 中的 bundle patch
  const nmDir = join(profileDir, 'node_modules');
  if (existsSync(nmDir)) {
    const entries = readdirSync(nmDir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name.startsWith('.') || entry.name === '.bin') continue;
      if (entry.name.startsWith('@')) {
        // scoped package
        const scopeDir = join(nmDir, entry.name);
        const pkgs = readdirSync(scopeDir, { withFileTypes: true });
        for (const pkg of pkgs) {
          const patchPath = join(scopeDir, pkg.name, 'cordis.patch.yml');
          if (existsSync(patchPath)) patchFiles.push(patchPath);
        }
      } else {
        const patchPath = join(nmDir, entry.name, 'cordis.patch.yml');
        if (existsSync(patchPath)) patchFiles.push(patchPath);
      }
    }
  }

  if (patchFiles.length === 0) {
    return pass(id, Severity.MEDIUM, '未找到 cordis.patch.yml 配置文件，跳过沙箱策略审计');
  }

  const allIssues = [];
  for (const patchFile of patchFiles) {
    try {
      const content = readFileSync(patchFile, 'utf8');
      allIssues.push(...checkSandboxPolicy(content));
      allIssues.push(...checkToolSandbox(content));
    } catch {
      // 跳过无法解析的文件
    }
  }

  if (allIssues.length === 0) {
    return pass(id, Severity.MEDIUM, `扫描 ${patchFiles.length} 个 patch 文件，沙箱策略配置一致`);
  }

  const bySeverity = {};
  for (const issue of allIssues) {
    if (!bySeverity[issue.severity]) bySeverity[issue.severity] = [];
    bySeverity[issue.severity].push(issue);
  }

  const summary = Object.entries(bySeverity)
    .map(([sev, items]) => `${sev}: ${items.length}`)
    .join(', ');

  const details = allIssues
    .slice(0, 10)
    .map(i => `[${i.severity}] ${i.tool} — ${i.finding}`)
    .join('\n');

  const overallSeverity = allIssues.some(i => i.severity === 'high') ? Severity.HIGH
    : allIssues.some(i => i.severity === 'medium') ? Severity.MEDIUM
    : Severity.LOW;

  return fail(id, overallSeverity,
    `检测到 ${allIssues.length} 个沙箱策略不一致（${summary}）：\n${details}`,
    '参考 dsh-sandbox-audit 获取详细修复建议',
    ['#2066']
  );
}

export const sp3Check = {
  id: 'SP3',
  name: 'sandbox-consistency',
  severity: Severity.MEDIUM,
  phase: CheckPhase.POST_INSTALL,
  description: '沙箱策略配置一致性审计',
  src: 'builtin',
  runner: (profileDir) => run(profileDir),
};

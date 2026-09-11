/**
 * SP3: Sandbox Consistency — 沙箱策略配置一致性审计
 *
 * 2026-09 上游兼容审计 R6 修复：真实的 sandbox/approval/permission 配置
 * **不在 profile 里**，而在 CLI 自带 bundle 的 patch 层与用户设置里：
 *   1. `@deepseek-ai/dsh-base/cordis.patch.yml`（经安装树解析）
 *      - `id: sandbox-policy` → `config.mode: !!js process.env.DSH_PERMISSION_MODE ?? 'workspace-write'`
 *      - `id: approval`       → `config.policy`（mode 为 danger-full-access 时 never，否则 ask）
 *      - `id: permission`     → `config.presets.{read-only,workspace-write,danger-full-access}`
 *   2. `$DSH_HOME/settings.yaml` → `permission.defaultPreset`
 *
 * 旧的 id 表已失效：`str_replace_editor` 是 tool *名* 而非 loader id，
 * `tool-glob` / `tool-grep` / `tool-fs-write` 已不存在（并入 `tool-fs-search`）。
 * 现在的 loader id 只有 `tool-fs` 与 `tool-fs-search`，沙箱由全局服务
 * `sandbox` / `sandbox-policy` 承载，而非逐工具声明。
 *
 * 每个配置源缺失时返回 **skip + 原因**，绝不因为"没扫到"就 PASS。
 *
 * Severity: MEDIUM（默认）
 * Phase: POST_INSTALL
 */

import { readFileSync, existsSync, realpathSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { homedir } from 'node:os';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail, skip } from '../protocol/check.mjs';

/** 真实存在的变文件系统工具 loader id（`str_replace_editor` 是 tool 名，不是 loader id） */
export const MUTATING_FS_TOOL_IDS = ['tool-fs'];

/** 真实存在的只读搜索工具 loader id（`tool-glob` / `tool-grep` 已并入它） */
export const READONLY_SEARCH_TOOL_IDS = ['tool-fs-search'];

/** 承载沙箱/审批/权限的真实服务 id */
export const SANDBOX_SERVICE_IDS = ['sandbox', 'sandbox-policy', 'bash-sandbox', 'pwsh-sandbox', 'approval', 'permission'];

/**
 * 解析 CLI 安装树里的 dsh-base bundle patch。
 * 顺序：显式覆盖 → profile 内 → module-fallback 锚点 → `which dsh` 指向的全局安装树。
 * @returns {string|null}
 */
export function resolveDshBasePatch(profileDir) {
  const candidates = [];
  if (process.env.DSH_BASE_PATCH) candidates.push(process.env.DSH_BASE_PATCH);
  if (profileDir) {
    candidates.push(join(profileDir, 'node_modules', '@deepseek-ai', 'dsh-base', 'cordis.patch.yml'));
    candidates.push(join(profileDir, '.dsh-module-fallback', 'node_modules', '@deepseek-ai', 'dsh-base', 'cordis.patch.yml'));
  }
  for (const candidate of candidates) {
    if (candidate && existsSync(candidate)) return candidate;
  }

  // 全局安装树：<prefix>/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-base/
  let whichRes;
  try {
    whichRes = spawnSync('which', ['dsh'], { encoding: 'utf8' });
  } catch {
    return null;
  }
  const binPath = ((whichRes && whichRes.stdout) || '').trim().split('\n').filter(Boolean)[0];
  if (!binPath) return null;

  let real = binPath;
  try { real = realpathSync(binPath); } catch { /* 用原路径 */ }

  let dir = dirname(real);
  for (let i = 0; i < 8; i++) {
    const candidate = join(dir, 'node_modules', '@deepseek-ai', 'dsh-base', 'cordis.patch.yml');
    if (existsSync(candidate)) return candidate;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

/** $DSH_HOME/settings.yaml（默认 ~/.dsh/settings.yaml） */
export function resolveSettingsPath() {
  const home = process.env.DSH_HOME && process.env.DSH_HOME.trim()
    ? process.env.DSH_HOME.trim()
    : join(homedir(), '.dsh');
  return join(home, 'settings.yaml');
}

/** 去掉一层首尾匹配引号 */
function stripOuterQuotes(s) {
  if (s.length >= 2 &&
      ((s.startsWith("'") && s.endsWith("'")) || (s.startsWith('"') && s.endsWith('"')))) {
    return s.slice(1, -1);
  }
  return s;
}

function stripInlineComment(s) {
  return s.replace(/\s+#.*$/, '').trim();
}

/**
 * 解析 YAML 标量：支持 `!!js` 表达式（含 `??` 默认值与三元表达式）与普通带引号标量。
 * 返回该表达式在"无环境覆盖"下的默认值；无法静态求值时返回 null。
 */
export function resolveJsDefault(raw) {
  if (raw === null || raw === undefined) return null;
  let s = stripInlineComment(String(raw));
  if (s.startsWith('!!js')) {
    s = stripOuterQuotes(s.slice(4).trim());
    // 三元表达式：取 else 分支（最后一个带引号的值）
    if (s.includes('?') && s.includes(':')) {
      const quoted = [...s.matchAll(/'([^']*)'|"([^"]*)"/g)].map(m => m[1] ?? m[2]);
      if (quoted.length) return quoted[quoted.length - 1];
    }
    const nullish = s.match(/\?\?\s*'([^']*)'|\?\?\s*"([^"]*)"/);
    if (nullish) return nullish[1] ?? nullish[2];
    const quoted = [...s.matchAll(/'([^']*)'|"([^"]*)"/g)].map(m => m[1] ?? m[2]);
    if (quoted.length) return quoted[quoted.length - 1];
    return null;
  }
  return stripOuterQuotes(s) || null;
}

/**
 * 从 patch 内容中切出 `- id: <x>` 条目块。
 * @returns {Array<{id: string, block: string, disabled: boolean}>}
 */
export function parseEntries(content) {
  const re = /^[ \t]*-[ \t]*id:[ \t]*['"]?([^'"\n]+?)['"]?[ \t]*$/gm;
  const matches = [];
  let m;
  while ((m = re.exec(content)) !== null) {
    matches.push({ id: m[1].trim(), index: m.index, end: m.index + m[0].length });
  }
  return matches.map((entry, i) => {
    const block = content.slice(entry.end, i + 1 < matches.length ? matches[i + 1].index : content.length);
    const disabledRaw = extractEntryScalar(block, 'disabled');
    return { id: entry.id, block, disabled: disabledRaw === 'true' };
  });
}

/** 在条目块里取一个顶层标量（如 `disabled:` / `mode:` / `policy:`） */
function extractEntryScalar(block, key) {
  const m = block.match(new RegExp(`^[ \\t]+${key}:[ \\t]*(.+?)[ \\t]*$`, 'm'));
  return m ? m[1] : null;
}

/** 解析 permission 条目的 `config.presets` 表 → { name: { sandbox, approval } } */
export function parsePresets(block) {
  const presets = {};
  const lines = block.split('\n');
  const start = lines.findIndex(l => /^[ \t]*presets:[ \t]*$/.test(l));
  if (start === -1) return presets;

  const baseIndent = lines[start].match(/^([ \t]*)/)[1].length;
  let current = null;
  for (let i = start + 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line.trim() || line.trim().startsWith('#')) continue;
    const indent = line.match(/^([ \t]*)/)[1].length;
    if (indent <= baseIndent) break;
    const presetName = line.match(/^[ \t]+([A-Za-z0-9_.-]+):[ \t]*$/);
    if (presetName && indent === baseIndent + 2) {
      current = presetName[1];
      presets[current] = {};
      continue;
    }
    const kv = line.match(/^[ \t]+([A-Za-z0-9_.-]+):[ \t]*(.+?)[ \t]*$/);
    if (kv && current) presets[current][kv[1]] = resolveJsDefault(kv[2]);
  }
  return presets;
}

/**
 * 从 settings.yaml 读取顶层 `permission.defaultPreset`。
 * 找不到 `permission` 命名空间或该键时返回 null。
 */
export function readDefaultPreset(content) {
  const lines = String(content).split('\n');
  let inPermission = false;
  for (const line of lines) {
    if (!line.trim() || line.trim().startsWith('#')) continue;
    const indent = line.match(/^([ \t]*)/)[1].length;
    if (/^permission:[ \t]*$/.test(line)) { inPermission = true; continue; }
    if (inPermission) {
      if (indent === 0) { inPermission = false; continue; }
      const m = line.match(/^[ \t]+defaultPreset:[ \t]*(.+?)[ \t]*$/);
      if (m) return resolveJsDefault(m[1]);
    }
  }
  return null;
}

/**
 * SP3 检查：沙箱/审批/权限解析配置一致性
 * @param {string} profileDir - profile 目录路径
 * @returns {Promise<import('../protocol/check.mjs').SecurityCheckResult>}
 */
export async function run(profileDir) {
  const id = 'SP3';
  const patchPath = resolveDshBasePatch(profileDir);
  const settingsPath = resolveSettingsPath();
  const settingsExists = existsSync(settingsPath);

  if (!patchPath) {
    const settingsNote = settingsExists
      ? '；settings.yaml 存在但缺少 dsh-base bundle patch，无法解析 permission presets 表'
      : '；settings.yaml 也不存在';
    return skip(id, Severity.MEDIUM,
      `未找到 @deepseek-ai/dsh-base/cordis.patch.yml（真实沙箱策略配置位置），跳过一致性审计${settingsNote}`);
  }

  let content;
  try {
    content = readFileSync(patchPath, 'utf8');
  } catch (e) {
    return skip(id, Severity.MEDIUM, `dsh-base patch 不可读（${patchPath}）：${e.message}，跳过一致性审计`);
  }

  const byId = new Map(parseEntries(content).filter(e => !e.disabled).map(e => [e.id, e]));
  const sandboxPolicy = byId.get('sandbox-policy');
  const approvalEntry = byId.get('approval');
  const permissionEntry = byId.get('permission');

  if (!sandboxPolicy && !approvalEntry && !permissionEntry) {
    return skip(id, Severity.MEDIUM,
      `dsh-base patch（${patchPath}）中未找到 sandbox-policy/approval/permission 条目，沙箱配置源缺失，跳过一致性审计`);
  }

  const issues = [];
  const envMode = (process.env.DSH_PERMISSION_MODE || '').trim() || null;
  const patchMode = sandboxPolicy ? resolveJsDefault(extractEntryScalar(sandboxPolicy.block, 'mode')) : null;
  const patchApproval = approvalEntry ? resolveJsDefault(extractEntryScalar(approvalEntry.block, 'policy')) : null;
  const presets = permissionEntry ? parsePresets(permissionEntry.block) : {};

  let settingsPreset = null;
  if (settingsExists) {
    try {
      settingsPreset = readDefaultPreset(readFileSync(settingsPath, 'utf8'));
    } catch {
      settingsPreset = null;
    }
  }

  let mode;
  let approvalPolicy;
  let source;

  if (envMode) {
    mode = envMode;
    approvalPolicy = envMode === 'danger-full-access' ? 'never' : 'ask';
    source = `DSH_PERMISSION_MODE=${envMode}（环境覆盖）`;
  } else if (settingsPreset) {
    if (presets[settingsPreset]) {
      mode = presets[settingsPreset].sandbox ?? patchMode;
      approvalPolicy = presets[settingsPreset].approval ?? patchApproval;
      source = `settings.yaml permission.defaultPreset=${settingsPreset}`;
    } else {
      issues.push({
        severity: 'medium',
        tool: 'permission.defaultPreset',
        finding: `settings.yaml 指定 permission.defaultPreset=${settingsPreset}，但 dsh-base patch 的 presets 表中没有该预设（可选：${Object.keys(presets).join(', ') || '无'}）`,
      });
      mode = patchMode;
      approvalPolicy = patchApproval;
      source = 'dsh-base patch 默认值（defaultPreset 无法解析）';
    }
  } else {
    mode = patchMode;
    approvalPolicy = patchApproval;
    source = 'dsh-base patch 默认值';
  }

  // 1) 沙箱被解析为完全放行（非 Windows）
  if (mode === 'danger-full-access' && process.platform !== 'win32') {
    issues.push({
      severity: 'medium',
      tool: 'sandbox-policy',
      finding: `沙箱模式解析为 danger-full-access（来源：${source}），非 Windows 下所有工具不受文件系统沙箱限制`
        + (approvalPolicy === 'never' ? '，且审批策略为 never（无人工闸门）' : ''),
    });
  }

  // 2) 审批闸门与沙箱模式不一致
  if (approvalPolicy === 'never' && mode && mode !== 'danger-full-access') {
    issues.push({
      severity: 'medium',
      tool: 'approval',
      finding: `审批策略解析为 never，但沙箱模式为 ${mode}（来源：${source}），二者不一致——审批闸门缺失而沙箱并未完全放行`,
    });
  }

  // 3) 解析出的 (sandbox, approval) 组合不对应任何已声明预设
  const presetNames = Object.keys(presets);
  if (mode && approvalPolicy && presetNames.length > 0 &&
      !presetNames.some(n => presets[n].sandbox === mode && presets[n].approval === approvalPolicy)) {
    issues.push({
      severity: 'low',
      tool: 'permission.presets',
      finding: `解析出的组合 sandbox=${mode} / approval=${approvalPolicy}（来源：${source}）不对应 presets 表中的任何预设（${presetNames.join(', ')}）`,
    });
  }

  // 4) 工具接线：工具 id 存在但全局沙箱服务缺失
  const presentSandboxServices = SANDBOX_SERVICE_IDS.filter(serviceId => byId.has(serviceId));
  const hasSandboxService = presentSandboxServices.includes('sandbox') || presentSandboxServices.includes('sandbox-policy');
  for (const toolId of MUTATING_FS_TOOL_IDS) {
    if (byId.has(toolId) && !hasSandboxService) {
      issues.push({
        severity: 'medium',
        tool: toolId,
        finding: `${toolId} 已挂载，但 bundle 中没有 sandbox/sandbox-policy 服务，文件系统工具可能使用 bare backend（策略被静默忽略）`,
      });
    }
  }
  for (const toolId of READONLY_SEARCH_TOOL_IDS) {
    if (byId.has(toolId) && !hasSandboxService) {
      issues.push({
        severity: 'low',
        tool: toolId,
        finding: `${toolId} 已挂载，但 bundle 中没有 sandbox/sandbox-policy 服务，只读搜索可能读取写策略外的路径`,
      });
    }
  }

  const sourceNote = [
    `patch=${patchPath}`,
    `settings=${settingsExists ? settingsPath : '不存在'}`,
    `mode=${mode ?? '未知'}`,
    `approval=${approvalPolicy ?? '未知'}`,
    `sandboxServices=${presentSandboxServices.join('+') || '无'}`,
  ].join(', ');

  if (issues.length === 0) {
    return pass(id, Severity.MEDIUM,
      `沙箱/审批/权限配置一致（${sourceNote}；来源：${source}）`);
  }

  const bySeverity = {};
  for (const issue of issues) {
    if (!bySeverity[issue.severity]) bySeverity[issue.severity] = [];
    bySeverity[issue.severity].push(issue);
  }
  const summary = Object.entries(bySeverity).map(([sev, items]) => `${sev}: ${items.length}`).join(', ');
  const details = issues.slice(0, 10).map(i => `[${i.severity}] ${i.tool} — ${i.finding}`).join('\n');

  const overallSeverity = issues.some(i => i.severity === 'high') ? Severity.HIGH
    : issues.some(i => i.severity === 'medium') ? Severity.MEDIUM
    : Severity.LOW;

  return fail(id, overallSeverity,
    `检测到 ${issues.length} 个沙箱配置不一致（${summary}；${sourceNote}）：\n${details}`,
    '核对 @deepseek-ai/dsh-base/cordis.patch.yml 的 sandbox-policy/approval/permission 与 $DSH_HOME/settings.yaml 的 permission.defaultPreset',
    ['#2066']
  );
}

export const sp3Check = {
  id: 'SP3',
  name: 'sandbox-consistency',
  severity: Severity.MEDIUM,
  phase: CheckPhase.POST_INSTALL,
  description: '沙箱策略配置一致性审计（dsh-base bundle patch + settings.yaml）',
  src: 'builtin',
  runner: (profileDir) => run(profileDir),
};

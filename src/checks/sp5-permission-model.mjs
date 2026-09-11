/**
 * SP5: Permission Model — 真实的插件能力面（不是不存在的 permissions 字段）
 *
 * 2026-09 上游兼容审计 R7——旧模型（v0.1.7 及以前）的门控是对的，模型是错的：
 * `dsh.bundle = { patch: './cordis.patch.yml' }` 确实存在（值得继续门控），
 * 但它**声称**要建模的 capability surface 并不存在——0.1.5 的插件 manifest
 * **没有 per-plugin `permissions` / `capabilities` 字段**。
 * 旧实现用 `cordis.patch.yml` 正文里的 `tool-fs|str_replace_editor` + `sandbox`
 * 字符串启发式去"检测未声明权限"，匹配不到任何真实声明，恒为 PASS。
 *
 * 真实的能力面是三处（全部可读、可机器判定）：
 *   (a) `dsh.client.inject` + `dsh.client.platform`
 *       —— 插件向 client 运行时注入的宿主模块清单（跨进程能力面）
 *   (b) `dsh.compatibility.{dsh, dshReleases, profiles}`
 *       —— 声明支持的 core 版本范围与被允许的 profile
 *   (c) 宿主侧 `permission` settings 命名空间（`$DSH_HOME/settings.yaml`
 *       → `permission.defaultPreset`；schema 仅此一键，
 *       dsh-permission-presets/lib/index.js:24,121-123）
 *       + `@deepseek-ai/dsh-base/cordis.patch.yml` 的
 *       `sandbox-policy.config.mode` / `approval.config.policy` / `permission.config.presets`
 *
 * 因此本检查改为**如实报告每个插件声明的能力面，以及哪些声明缺失 = 默认不受约束**：
 *   - 声明了 `dsh.client.inject` 但既无 `dsh.compatibility` 也无 profile 限制
 *     → 跨进程能力面完全无版本/配置约束（MEDIUM）
 *   - `dsh.compatibility.dsh` 范围**排除**了安装闭包实际提供的 core 版本（MEDIUM）
 *   - `dsh.compatibility.profiles` 不含当前 profile（MEDIUM）
 *   - manifest 里出现 `permissions` / `capabilities` 键：宿主无此 schema，
 *     声明不会被强制执行（MEDIUM，避免把"写了"误当成"受限"）
 *   - 无法精确判定版本归属时**不猜**（node-semver 缺失 → 近似法只在确定时给结论）
 *
 * Severity: MEDIUM
 * Phase: POST_INSTALL
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { createResult, fail, skip } from '../protocol/check.mjs';
import {
  listPackageDirs,
  resolveDshHome,
  resolveCoreVersions,
  resolveInstallPrefix,
  resolveSemver,
  checkRange,
} from '../install-tree.mjs';
import { readPermissionSettings, readHostSandboxConfig, resolveBasePatch } from '../dsh-config.mjs';

/** 宿主 manifest 里**不存在**的能力声明键——出现即说明作者误以为它会被强制 */
const NONEXISTENT_DECL_KEYS = ['permissions', 'capabilities', 'allowedTools'];

/** CLI 安装根候选（用于定位 dsh-base 的 patch 与 semver） */
function cliRootCandidates(profileDir) {
  const prefix = resolveInstallPrefix(profileDir);
  return [prefix ? join(prefix, 'dsh') : null, prefix].filter(Boolean);
}

/** 读取宿主侧真实权限面 */
function readHostSurface(profileDir, options = {}) {
  const dshHome = options.dshHome !== undefined ? options.dshHome : resolveDshHome(profileDir);
  const cliRoots = cliRootCandidates(profileDir);
  const basePatchPath = options.basePatchPath !== undefined
    ? options.basePatchPath
    : resolveBasePatch(profileDir, cliRoots);
  return {
    dshHome,
    basePatchPath,
    permission: readPermissionSettings(dshHome),
    sandbox: readHostSandboxConfig(basePatchPath),
  };
}

function describeHost(host) {
  const parts = [];
  if (host.permission.file && host.permission.present) {
    parts.push(`settings.yaml permission.defaultPreset=${host.permission.defaultPreset ?? '(空)'}`);
  } else {
    parts.push(`settings.yaml 未配置 permission.defaultPreset（宿主按 sandbox/approval 默认值推断 preset）`);
  }
  if (!host.sandbox) {
    parts.push(`未找到 dsh-base/cordis.patch.yml（无法读取 sandbox-policy/approval 实际配置）`);
    return parts.join('；');
  }
  const mode = host.sandbox.sandboxMode;
  const approval = host.sandbox.approvalPolicy;
  const modeText = mode
    ? (mode.expression
      ? `!!js ${mode.expression}${mode.literal ? `（默认字面量 ${mode.literal}）` : ''}`
      : mode.literal)
    : '(未声明)';
  const apprText = approval
    ? (approval.expression && !approval.decisive ? '由沙箱模式派生（danger-full-access → never，否则 ask）' : (approval.literal ?? '(空)'))
    : '(未声明)';
  parts.push(`sandbox-policy.mode=${modeText}`);
  parts.push(`approval.policy=${apprText}`);
  const presetNames = Object.keys(host.sandbox.presets || {});
  if (presetNames.length > 0) {
    parts.push(`presets=${presetNames.map(n => `${n}{sandbox:${host.sandbox.presets[n].sandbox},approval:${host.sandbox.presets[n].approval}}`).join(' ')}`);
  }
  return parts.join('；');
}

/** 单个插件的声明面 */
function inspectPlugin(pkgJsonPath, displayName, ctx) {
  let pkg;
  try { pkg = JSON.parse(readFileSync(pkgJsonPath, 'utf8')); } catch { return null; }
  const dsh = pkg && pkg.dsh;
  if (!dsh || typeof dsh !== 'object') return null;

  const declared = {
    name: pkg.name || displayName,
    bundlePatch: null,
    clientInject: [],
    clientPlatform: null,
    compatDsh: null,
    compatReleases: [],
    compatProfiles: [],
    unknownKeys: [],
  };

  if (dsh.bundle && dsh.bundle.patch) declared.bundlePatch = String(dsh.bundle.patch);
  if (dsh.client && typeof dsh.client === 'object') {
    if (Array.isArray(dsh.client.inject)) declared.clientInject = dsh.client.inject.filter(x => typeof x === 'string');
    if (typeof dsh.client.platform === 'string') declared.clientPlatform = dsh.client.platform;
  }
  if (dsh.compatibility && typeof dsh.compatibility === 'object') {
    if (typeof dsh.compatibility.dsh === 'string') declared.compatDsh = dsh.compatibility.dsh;
    if (dsh.compatibility.dshReleases && typeof dsh.compatibility.dshReleases === 'object') {
      declared.compatReleases = Object.keys(dsh.compatibility.dshReleases);
    }
    if (Array.isArray(dsh.compatibility.profiles)) {
      declared.compatProfiles = dsh.compatibility.profiles.filter(x => typeof x === 'string');
    }
  }
  for (const k of NONEXISTENT_DECL_KEYS) {
    if (Object.prototype.hasOwnProperty.call(dsh, k)) declared.unknownKeys.push(k);
  }

  const findings = [];
  const dshRoot = ctx.coreVersions['@deepseek-ai/dsh'];
  const dshBase = ctx.coreVersions['@deepseek-ai/dsh-base'];
  // 以 profile 侧安装闭包实际提供的版本为准（dsh-base 是 profile 的 bundle 根），
  // CLI 自身那份仅作兜底——两者同属安装闭包，都会在诊断里如实列出。
  const provided = dshBase?.version || dshRoot?.version || null;

  if (declared.unknownKeys.length > 0) {
    findings.push({
      severity: 'medium',
      type: 'unrecognized-capability-declaration',
      detail: `${declared.name} 的 manifest 声明了 dsh.${declared.unknownKeys.join('/dsh.')}——` +
        `该字段在 0.1.5 宿主 manifest schema 中不存在，声明不会被强制执行（若作者以此认定权限已受限，则属于误信）`,
    });
  }

  if (declared.compatDsh && provided) {
    const r = checkRange(provided, declared.compatDsh, ctx.semverMod);
    if (r.satisfies === false) {
      findings.push({
        severity: 'medium',
        type: 'declared-core-range-excludes-provided',
        detail: `${declared.name} 声明 dsh 兼容范围「${declared.compatDsh}」，` +
          `但安装闭包实际提供 ${provided}${r.exact ? '' : '（近似判定，node-semver 不可用）'}——该插件未声明支持当前 core 版本`,
      });
    }
  }

  if (declared.compatProfiles.length > 0 && ctx.profileName && !declared.compatProfiles.includes(ctx.profileName)) {
    findings.push({
      severity: 'medium',
      type: 'profile-not-declared',
      detail: `${declared.name} 的 dsh.compatibility.profiles=[${declared.compatProfiles.join(', ')}] 不含当前 profile「${ctx.profileName}」`,
    });
  }

  if (declared.clientInject.length > 0 && !declared.compatDsh && declared.compatProfiles.length === 0) {
    findings.push({
      severity: 'medium',
      type: 'cross-process-surface-unconstrained',
      detail: `${declared.name} 向 client 运行时注入 ${declared.clientInject.length} 个宿主模块` +
        `（${declared.clientInject.slice(0, 4).join(', ')}${declared.clientInject.length > 4 ? ' …' : ''}），` +
        `却既无 dsh.compatibility.dsh 也无 profiles 限制——该跨进程能力面对 core 版本/配置完全无约束声明`,
    });
  }

  if (!declared.bundlePatch && !dsh.client) {
    // 无 bundle patch 且无 client 注入：该包不是可装载插件，不参与能力面统计
    return { declared, findings, plugin: false };
  }
  return { declared, findings, plugin: true };
}

export async function run(profileDir, options = {}) {
  const id = 'SP5';
  const nmDir = join(profileDir, 'node_modules');
  if (!existsSync(nmDir)) {
    return skip(id, Severity.MEDIUM,
      `无 node_modules（${nmDir}），未执行插件能力面审计——无法读取任何 manifest 声明`);
  }

  const host = readHostSurface(profileDir, options);
  // 让 SP9/安装树解析出的实际 profile 名参与 profiles 一致性判定
  const layoutName = (() => {
    const m = /[/\\]profiles[/\\]([^/\\]+)$/.exec(String(profileDir));
    return m ? m[1] : null;
  })();

  const ctx = {
    coreVersions: resolveCoreVersions(profileDir),
    semverMod: options.semverMod !== undefined
      ? options.semverMod
      : (resolveSemver(profileDir, cliRootCandidates(profileDir))?.mod ?? null),
    profileName: options.profileName !== undefined ? options.profileName : layoutName,
  };

  const dirs = listPackageDirs(nmDir);
  const plugins = [];
  const findings = [];
  for (const entry of dirs) {
    const pkgJson = join(entry.dir, 'package.json');
    if (!existsSync(pkgJson)) continue;
    const res = inspectPlugin(pkgJson, entry.name, ctx);
    if (!res) continue;
    if (res.plugin) plugins.push(res.declared);
    findings.push(...res.findings);
  }

  if (plugins.length === 0) {
    return skip(id, Severity.MEDIUM,
      `${nmDir} 下未找到任何带 dsh 声明的插件包（0 个），未执行能力面审计——无法判定声明覆盖情况` +
      `\n宿主侧真实权限面: ${describeHost(host)}`);
  }

  const declaredCount = plugins.filter(p => p.compatDsh || p.compatProfiles.length > 0).length;
  const unconstrained = plugins.filter(p => !p.compatDsh && p.compatProfiles.length === 0);
  const hostLine = `宿主侧真实权限面: ${describeHost(host)}`;
  const envOverride = ['DSH_PERMISSION_MODE', 'DSH_TOOLS_MODE'].filter(k => process.env[k]);
  const envLine = envOverride.length > 0
    ? `当前进程环境覆盖: ${envOverride.map(k => `${k}=${process.env[k]}`).join(', ')}（运行期可覆盖上面 written config）`
    : `当前进程无 DSH_PERMISSION_MODE / DSH_TOOLS_MODE 覆盖`;
  const coreLine = `安装闭包提供: @deepseek-ai/dsh=${ctx.coreVersions['@deepseek-ai/dsh']?.version || '?'}` +
    `, dsh-base=${ctx.coreVersions['@deepseek-ai/dsh-base']?.version || '?'}` +
    (ctx.semverMod ? '（版本范围判定用 node-semver）' : '（node-semver 不可用，仅近似判定，不确定一律不报）');

  const perPlugin = plugins.map(p => {
    const bits = [];
    if (p.bundlePatch) bits.push(`bundle.patch=${p.bundlePatch}`);
    if (p.clientInject.length > 0) bits.push(`client.inject=${p.clientInject.length}${p.clientPlatform ? `/${p.clientPlatform}` : ''}`);
    else if (p.clientPlatform) bits.push(`client.platform=${p.clientPlatform}`);
    if (p.compatDsh) bits.push(`compat.dsh=${p.compatDsh}`);
    else if (p.compatReleases.length > 0) bits.push(`compat.dshReleases=${p.compatReleases.length}`);
    if (p.compatProfiles.length > 0) bits.push(`compat.profiles=[${p.compatProfiles.join(',')}]`);
    if (p.unknownKeys.length > 0) bits.push(`dsh.${p.unknownKeys.join('/dsh.')}=（宿主无此 schema）`);
    const constrained = p.compatDsh || p.compatProfiles.length > 0;
    return `  ${p.name}: ${bits.join(' ') || '(仅 dsh 存在，无声明字段)'}${constrained ? '' : '  ← 无兼容/配置约束声明'}`;
  }).join('\n');

  const summaryLine =
    `插件能力面: 共 ${plugins.length} 个带 dsh 声明的插件，其中 ${declaredCount} 个声明了 compat.dsh/profiles，` +
    `${unconstrained.length} 个未做任何兼容/配置约束声明` +
    (unconstrained.length > 0 ? `（${unconstrained.slice(0, 6).map(p => p.name).join(', ')}${unconstrained.length > 6 ? ' …' : ''}）` : '');

  const body = `${summaryLine}\n${hostLine}\n${envLine}\n${coreLine}\n逐插件声明:\n${perPlugin}`;

  if (findings.length === 0) {
    return createResult(id, true, Severity.MEDIUM,
      `未发现能力面声明问题（未声明 ≠ 已受限：宿主默认按 preset/sandbox 配置执行）\n${body}`);
  }

  const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const top = findings.reduce((a, b) => (order[b.severity] < order[a.severity] ? b : a), findings[0]);
  const detail = findings.slice(0, 12).map(f => `[${f.severity}] ${f.type}: ${f.detail}`).join('\n');
  const more = findings.length > 12 ? `\n…另有 ${findings.length - 12} 项` : '';
  return fail(id, top.severity,
    `检测到 ${findings.length} 项能力面声明问题：\n${detail}${more}\n${body}`,
    '插件应在 manifest 里声明 dsh.compatibility.{dsh,profiles}（真实存在的字段）；' +
    '不要写 dsh.permissions/dsh.capabilities（宿主无此 schema，不会被强制）；' +
    '宿主侧用 settings.yaml 的 permission.defaultPreset 与 dsh-base 的 sandbox-policy/approval 收紧默认档位'
  );
}

export const sp5Check = {
  id: 'SP5',
  name: 'permission-model',
  severity: Severity.MEDIUM,
  phase: CheckPhase.POST_INSTALL,
  description: '插件能力面审计——读真实的 dsh.bundle / dsh.client.inject / dsh.compatibility 与宿主 permission/sandbox 配置（宿主无 per-plugin permissions 字段）',
  src: 'builtin',
  runner: (d) => run(d),
};

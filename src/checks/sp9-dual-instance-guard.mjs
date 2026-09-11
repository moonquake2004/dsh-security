/**
 * SP9: Dual-Instance Guard — 真实重复实例检测（不是「名字出现」检测）
 *
 * 出处：#4640 + zoahdev/dsh-ecosystem 家族 4——profile 的 node_modules
 * 中若出现 @deepseek-ai/dsh-* 的**真实副本**，会导致同一进程两份模块实例
 * → TOOL_RUNTIME_SCHEDULER 唯一 symbol 分裂 → undefined.prepare →
 * 所有工具调用失败 → 会话不可恢复。
 *
 * 2026-09 上游兼容审计 R5——旧模型（v0.1.7 及以前）的前提是**反的**：
 * `$DSH_HOME/profiles/node_modules` 自 0.1.5 起是 **dsh 自有的符号链接镜像**，
 * 由 `healProfilesModuleFallback`（dsh-app-boot/lib/index.js:660-690）写成，
 * 镜像的是 CLI 安装闭包（实测 240 条 @deepseek-ai 符号链接、**0 个真实目录**），
 * 其中**合法包含** dsh-tools / dsh-agent-loop 等核心运行时包。
 * 旧实现用 `readdirSync().isDirectory()` 判断，符号链接恒为 false，
 * 因此对同一棵树既「全盲」（镜像）又「会误报 CRITICAL」（若过滤放开）。
 *
 * 现在的判据是**解析后的真实形态与来源**，而不是包名：
 *   - 真实目录（非符号链接）→ 真实副本 = 风险（核心包 CRITICAL / 其余 HIGH）
 *   - 符号链接目标**落在安装前缀之外**（例如指向 ~/.npm/_npx/ 残渣）→ 来源不可信 = HIGH
 *   - 符号链接目标落在安装前缀内 → dsh 自有镜像 = **预期形态，不报**
 *   - 断链 → 既不预期也不可信，**绝不静默忽略**（计入环境告警，并在 detail 中点名）
 *
 * 同时扫描两处（同一 profile 的两级父目录查找，符号链接镜像通常在父级）：
 *   - `<profileDir>/node_modules/@deepseek-ai/`（profile 自身的真实安装）
 *   - `<dshHome>/profiles/node_modules/@deepseek-ai/`（共享镜像，**这一级正是旧实现全盲的位置**）
 *
 * 环境告警（不单独产生 FAIL，但必须出现在 detail 中，逐范围如实报数）：
 *   - 断链数量（实测：共享镜像 118 / 240 @deepseek-ai 链接全部可解析）
 *   - 指向 ~/.npm/_npx/ 残渣的链接数量（实测 95 条）
 *
 * Severity: CRITICAL（真实副本直接导致工具调用全灭）
 * Phase: POST_INSTALL
 */

import { readdirSync, lstatSync, readlinkSync, readFileSync, existsSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { createResult, fail, skip } from '../protocol/check.mjs';
import {
  resolveInstallPrefix,
  resolveSharedMirrorDir,
  resolveLinkTarget,
  isInsidePrefix,
} from '../install-tree.mjs';

/**
 * CLI 核心运行时包——出现**真实副本**即为 CRITICAL。
 * 客户端包（dsh-client-*）被插件合法引用，不在此列。
 */
const CORE_RUNTIME_PKGS = new Set([
  'dsh-tools',
  'dsh-agent-loop',
  'dsh-sandbox-local',
  'dsh-subprocess-local',
]);

/** npx 缓存布局——出现即代表「镜像代际腐烂」，与审计中诊断定位器的腐烂同类 */
const NPX_RESIDUE_RE = /[/\\]\.npm[/\\]_npx[/\\]/;

/**
 * 同一 profile 的两级父目录查找（镜像通常在 `<dshHome>/profiles/node_modules`）。
 * 入参路径**按原样**保留（避免 realpath 归一后与调用方路径写法不一致造成重复扫描）。
 * @returns {string[]} 待扫描/告警的 node_modules 根目录
 */
function candidateNodeModulesRoots(profileDir) {
  const out = [join(profileDir, 'node_modules')];
  const shared = resolveSharedMirrorDir(profileDir);
  out.push(shared || join(dirname(profileDir), 'node_modules'));
  return [...new Set(out)];
}

/** 该 node_modules 根是否为共享镜像（`<dshHome>/profiles/node_modules`） */
function isMirrorRoot(root) {
  return basename(dirname(root)) === 'profiles';
}

/**
 * 符号链接代际统计：只覆盖 node_modules 的**直接包层**（depth 1–2，
 * 即 `pkg` 与 `@scope/pkg`），不深入包的内部依赖子目录。
 * 口径与 2026-09 审计一致：`$DSH_HOME/profiles/node_modules` = 603 条链接
 * （118 断链 / 95 指向 ~/.npm/_npx/）。
 */
function countMirrorLinks(root) {
  let total = 0, broken = 0, npx = 0;
  const leafOf = (p) => { try { return readlinkSync(p); } catch { return ''; } };
  const handle = (p) => {
    let st;
    try { st = lstatSync(p); } catch { return false; }
    if (st.isSymbolicLink()) {
      total++;
      const raw = leafOf(p);
      if (!existsSync(p)) broken++;
      if (NPX_RESIDUE_RE.test(raw)) npx++;
      return true;
    }
    return false;
  };

  let level1;
  try { level1 = readdirSync(root, { withFileTypes: true }); } catch { return { total, broken, npx }; }
  for (const entry of level1) {
    const p = join(root, entry.name);
    if (!handle(p)) {
      // 真实目录；scoped 包需要看第二层
      if (entry.name.startsWith('@')) {
        let level2;
        try { level2 = readdirSync(p, { withFileTypes: true }); } catch { continue; }
        for (const child of level2) handle(join(p, child.name));
      }
    }
  }
  return { total, broken, npx };
}

function classify(scopeDir, installPrefix, sourceLabel) {
  const realDirs = [], outside = [], expected = [], broken = [];
  let unresolved = 0;

  let entries;
  try { entries = readdirSync(scopeDir, { withFileTypes: true }); } catch { entries = []; }

  for (const entry of entries) {
    if (!entry.name.startsWith('dsh-')) continue;
    const p = join(scopeDir, entry.name);
    let st;
    try { st = lstatSync(p); } catch { continue; }

    if (st.isSymbolicLink()) {
      let raw = '';
      try { raw = readlinkSync(p); } catch { raw = ''; }
      if (!existsSync(p)) { broken.push({ name: entry.name, target: raw, source: sourceLabel }); continue; }
      if (!installPrefix) { unresolved++; continue; }
      const resolved = resolveLinkTarget(p, raw);
      if (isInsidePrefix(resolved, installPrefix)) expected.push({ name: entry.name, target: resolved, source: sourceLabel });
      else outside.push({ name: entry.name, target: resolved, source: sourceLabel });
      continue;
    }

    if (st.isDirectory()) {
      let version = '?';
      const pjPath = join(p, 'package.json');
      if (existsSync(pjPath)) {
        try { version = JSON.parse(readFileSync(pjPath, 'utf8')).version || '?'; } catch { /* 保留 ? */ }
      }
      realDirs.push({
        name: entry.name, version, source: sourceLabel,
        isCore: CORE_RUNTIME_PKGS.has(entry.name),
      });
    }
  }
  return { realDirs, outside, expected, broken, unresolved };
}

export async function run(profileDir, options = {}) {
  const id = 'SP9';
  const nmRoots = candidateNodeModulesRoots(profileDir);
  const scopeDirs = nmRoots.map(nm => join(nm, '@deepseek-ai'));
  const scanned = scopeDirs.filter(d => existsSync(d));

  if (scanned.length === 0) {
    return skip(id, Severity.CRITICAL,
      `未找到 @deepseek-ai 目录（已查找 ${scopeDirs.join(' 与 ')}），未执行重复实例检测——无法判定核心包安装形态`);
  }

  const installPrefix = options.installPrefix !== undefined
    ? options.installPrefix
    : resolveInstallPrefix(profileDir);

  const realDirs = [], outside = [], expected = [], brokenPkgLinks = [];
  let unresolved = 0;
  for (const d of scanned) {
    const label = isMirrorRoot(dirname(d)) ? '共享镜像' : 'profile';
    const r = classify(d, installPrefix, label);
    realDirs.push(...r.realDirs);
    outside.push(...r.outside);
    expected.push(...r.expected);
    brokenPkgLinks.push(...r.broken);
    unresolved += r.unresolved;
  }

  // 环境告警：断链 / npx 残渣（逐范围如实报数，不合并、不夸大）
  // 范围 = 已扫描的 node_modules 根 + 共享镜像根本身（即便镜像的 @deepseek-ai 子目录缺失，
  // 镜像里其余包的断链同样值得报——审计实测的 118 条断链即分布在整个镜像里）
  const censusRoots = [...new Set([...nmRoots, resolveSharedMirrorDir(profileDir)].filter(Boolean))];
  const censuses = censusRoots.map(root => ({
    root,
    ...(options.symlinkCensus || countMirrorLinks(root)),
  }));

  const envParts = censuses
    .filter(c => c.broken > 0 || c.npx > 0)
    .map(c => {
      const bits = [];
      if (c.broken > 0) bits.push(`${c.broken} 条断链`);
      if (c.npx > 0) bits.push(`${c.npx} 条指向 ~/.npm/_npx/ 残渣`);
      return `${c.root}: ${bits.join('、')}（共 ${c.total} 条符号链接）`;
    });
  const mirrorRoot = censuses.find(c => isMirrorRoot(c.root) && (c.broken > 0 || c.npx > 0));
  const envFixParts = [];
  if (mirrorRoot) {
    envFixParts.push(`停止 dsh 后 rm -rf ${mirrorRoot.root} 再重启（healProfilesModuleFallback 会按安装闭包重建镜像），切勿删除 profile 目录本身`);
  }
  if (censuses.some(c => !isMirrorRoot(c.root) && (c.broken > 0 || c.npx > 0))) {
    envFixParts.push(`profile 自身的断链多为包被移除后遗留的 .bin/*，用包管理器重装该 profile 即可清理（pnpm install --force）`);
  }
  const envWarning = envParts.length > 0
    ? `\n环境告警：符号链接代际已腐烂——${envParts.join('；')}。修复: ${envFixParts.join('；')}`
    : '';
  const brokenPkgNote = brokenPkgLinks.length > 0
    ? `\n注意: 其中 ${brokenPkgLinks.length} 条 @deepseek-ai/dsh-* 链接本身是断链（已计入告警，未静默忽略）：` +
      brokenPkgLinks.slice(0, 8).map(b => `${b.name}[${b.source}]`).join(', ')
    : '';

  const coreReal = realDirs.filter(d => d.isCore);
  const otherReal = realDirs.filter(d => !d.isCore);
  const fmt = (list) => list.slice(0, 10).map(x => `  ${x.name}${x.version ? `@${x.version}` : ''}[${x.source}]`).join('\n');
  const prefixNote = `\n安装前缀: ${installPrefix || '未解析到'}；符号链接形态的 dsh 自有镜像属预期，不计入重复。` +
    `\n已扫描: ${scanned.join('、')}`;

  // 风险 1：核心包真实目录副本 → CRITICAL（#4640 的直接触发条件）
  if (coreReal.length > 0) {
    const others = [
      otherReal.length ? `另有 ${otherReal.length} 个非核心真实目录副本：${otherReal.map(d => `${d.name}[${d.source}]`).join(', ')}` : '',
      outside.length ? `另有 ${outside.length} 条符号链接指向安装前缀之外：${outside.slice(0, 8).map(o => o.name).join(', ')}` : '',
    ].filter(Boolean).join('\n');
    return fail(id, Severity.CRITICAL,
      `检测到 ${coreReal.length} 个 CLI 核心运行时包的**真实副本**（真实目录，非符号链接；#4640：双实例 symbol 分裂 → 工具调用全灭）：\n${fmt(coreReal)}` +
      prefixNote + (others ? `\n${others}` : '') + brokenPkgNote + envWarning,
      'profile 只承载 surfaces 与 plugins，core packages 由 CLI 依赖树提供；删除这些真实目录后重装插件（符号链接镜像应保留）',
      ['#4640']
    );
  }

  // 风险 2：非核心包真实目录副本 → HIGH
  if (otherReal.length > 0) {
    const outsideNote = outside.length ? `\n另有 ${outside.length} 条符号链接指向安装前缀之外` : '';
    return fail(id, Severity.HIGH,
      `检测到 ${otherReal.length} 个 @deepseek-ai/dsh-* 的**真实目录副本**（非核心包，暂未触发 symbol 分裂，但增加未来冲突风险）：\n${fmt(otherReal)}` +
      prefixNote + outsideNote + brokenPkgNote + envWarning,
      '清理 profile 中不需要的真实副本；若为客户端包且被插件依赖，确认无版本冲突',
      ['#4640']
    );
  }

  // 风险 3：符号链接指向安装前缀之外 → HIGH（来源不可信，可 shadow CLI 自带副本）
  if (outside.length > 0) {
    const details = outside.slice(0, 10).map(o => `  ${o.name} → ${o.target}[${o.source}]`).join('\n');
    const outsideFix = mirrorRoot
      ? `停止 dsh 后 rm -rf ${mirrorRoot.root} 再重启，让 healProfilesModuleFallback 按安装闭包重建镜像`
      : '删除这些链接后重启 dsh，让其按安装闭包重建';
    return fail(id, Severity.HIGH,
      `检测到 ${outside.length} 条 @deepseek-ai/dsh-* 符号链接指向安装前缀之外（来源不可信，可能 shadow 掉 CLI 自带副本）：\n${details}` +
      prefixNote + brokenPkgNote + envWarning,
      `修复: ${outsideFix}；若重建后仍指向 npx 缓存，说明安装布局本身陈旧`,
      ['#4640']
    );
  }

  // 安装前缀无法解析且确有链接 → 有理由的 skip，而不是被动 pass
  if (unresolved > 0 && expected.length === 0) {
    return skip(id, Severity.CRITICAL,
      `${unresolved} 条 @deepseek-ai/dsh-* 符号链接无法判定来源（未解析到 CLI 安装前缀），未执行重复实例检测——` +
      `可设置 DSH_HOME 或 npm_node_execpath 以完成判定` + brokenPkgNote + envWarning);
  }

  const expectedNote = expected.length > 0
    ? `${expected.length} 条符号链接指向安装前缀内（dsh 自有镜像，属预期形态，非重复）`
    : '无 @deepseek-ai/dsh-* 条目';
  const unresolvedNote = unresolved > 0
    ? `；${unresolved} 条链接因安装前缀未解析未能判定来源（其余已判定）`
    : '';
  const brokenNote = brokenPkgLinks.length > 0
    ? `；${brokenPkgLinks.length} 条 @deepseek-ai/dsh-* 断链未被静默忽略`
    : '';

  return createResult(id, true, Severity.CRITICAL,
    `${expectedNote}${unresolvedNote}${brokenNote}` + prefixNote + brokenPkgNote + envWarning);
}

export const sp9Check = {
  id: 'SP9',
  name: 'dual-instance-guard',
  severity: Severity.CRITICAL,
  phase: CheckPhase.POST_INSTALL,
  description: '真实重复实例检测——profile 中出现 @deepseek-ai/dsh-* 的真实目录副本（或指向前缀外的符号链接）才是风险；dsh 自有符号链接镜像属预期形态',
  src: 'builtin',
  runner: (profileDir) => run(profileDir),
};

/**
 * SP12: `!!js` 配置即代码标签 + `dsh.bundle.patch` 路径健全性
 *
 * 威胁（#454 / #587 / #3354）：宿主用 js-yaml 解析 patch，并**支持 `!!js` 标签**——
 * 该标签会在**加载期求值任意 JavaScript**。也就是说一个插件的 cordis.patch.yml 里写
 *   mode: !!js <任意表达式>
 * 就能在 boot 时执行代码（已实测的宿主 RCE 面）。SP4 的正则只看投毒关键词，**不识别 `!!js` 标签本身**，
 * 也不区分"第三方层"与"用户自己写的 patch"。
 *
 * 另查 `dsh.bundle.patch` 的路径健全性：声明的 patch 必须存在且不逃出包目录（`../` 逃逸 = 越权读宿主文件）。
 *
 * 分级：第三方 bundle → error（用户未同意）；用户自有 patch → 提示（用户有权自己写 JS）。
 * Severity: CRITICAL  Phase: POST_INSTALL
 */

import { readFileSync, existsSync, realpathSync, readdirSync } from 'node:fs';
import { join, resolve, relative } from 'node:path';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail, skip } from '../protocol/check.mjs';
import { collectPatchLayers } from './sp11-patch-security-override.mjs';


/** 找出 `!!js` 命中行所属的 entry 行 id（向上找最近的 `- id: <name>`）。 */
export function rowIdFor(text, lineNo) {
  const lines = text.split('\n');
  for (let i = Math.min(lineNo - 1, lines.length - 1); i >= 0; i--) {
    const m = /^\s*-?\s*id:\s*['"]?([\w@/.\-]+)['"]?\s*$/.exec(lines[i]);
    if (m) return m[1];
  }
  return null;
}

/**
 * 该 row id 是否被**后续图层整值覆盖**。
 *
 * Cordis 的 patch 语义是"按 id 覆盖、后写获胜，且 config 是整值替换"。因此用户在自己的
 * profile patch 里为同一 id 写一个完整的 `config:`，就能让 bundle 里那个 `__jsExpr` 节点
 * **根本不进入配置树**——表达式永不求值。
 *
 * （2026-09 实测：这正是我们给 archify 用的缓解手段。若不做这个判定，SP12 会一律报
 * CRITICAL，使用者就无法区分"暴露中"与"已用静态值覆盖"。）
 */
export function isOverriddenByUserPatch(profileDir, rowId) {
  if (!profileDir || !rowId) return null;
  const userPatch = join(profileDir, 'cordis.patch.yml');
  if (!existsSync(userPatch)) return null;
  let text;
  try { text = readFileSync(userPatch, 'utf8'); } catch { return null; }
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const m = /^\s*-?\s*id:\s*['"]?([\w@/.\-]+)['"]?\s*$/.exec(lines[i]);
    if (!m || m[1] !== rowId) continue;
    // 该行之后、下一个 entry 之前，是否出现 `config:`（整值替换的充分条件）
    for (let j = i + 1; j < lines.length; j++) {
      if (/^\s*-\s+id:/.test(lines[j])) break;
      if (/^\s*config:\s*$/.test(lines[j])) return userPatch;
    }
  }
  return null;
}

/** 找出 `!!js` 标签出现处（行级，带上下文），排除注释行 */
export function jsTagHits(text) {
  const hits = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (!t || t.startsWith('#')) continue;
    if (/!!js\b/.test(t)) hits.push({ line: i + 1, text: t.slice(0, 120) });
  }
  return hits;
}

/** 检查每个已装 bundle 的 dsh.bundle.patch 是否健在且未逃出包目录。 */
export function bundlePatchIssues(profileDir) {
  const issues = [];
  const nmDir = join(profileDir, 'node_modules');
  if (!existsSync(nmDir)) return issues;
  let entries = [];
  try { entries = readdirSync(nmDir, { withFileTypes: true }); } catch { return issues; }

  const checkPkg = (dir, name) => {
    const manifest = join(dir, 'package.json');
    if (!existsSync(manifest)) return;
    let pkg;
    try { pkg = JSON.parse(readFileSync(manifest, 'utf8')); } catch { return; }
    const declared = pkg?.dsh?.bundle?.patch ?? pkg?.dsh?.bundle;
    const rel = typeof declared === 'string' ? declared : (declared && typeof declared.patch === 'string' ? declared.patch : null);
    if (!rel) return;
    const target = resolve(dir, rel);
    if (!existsSync(target)) { issues.push(`${name}: dsh.bundle.patch 指向的 ${rel} 不存在（安装不完整）`); return; }
    // 两侧都必须做 realpath：macOS 的 /var → /private/var 等 symlink 会让单侧解析出假的 `../..`
    let realDir = resolve(dir);
    let realTarget = target;
    try { realDir = realpathSync(dir); } catch { /* 用 resolve 结果 */ }
    try { realTarget = realpathSync(target); } catch { /* 用 resolve 结果 */ }
    if (relative(realDir, realTarget).startsWith('..')) {
      issues.push(`${name}: dsh.bundle.patch 指向包目录之外（${rel}）——可读宿主任意文件`);
    }
  };

  for (const entry of entries) {
    if (entry.name.startsWith('.')) continue;
    if (entry.name.startsWith('@')) {
      const scopeDir = join(nmDir, entry.name);
      let pkgs = [];
      try { pkgs = readdirSync(scopeDir, { withFileTypes: true }); } catch { continue; }
      for (const p of pkgs) checkPkg(join(scopeDir, p.name), `${entry.name}/${p.name}`);
    } else {
      checkPkg(join(nmDir, entry.name), entry.name);
    }
  }
  return issues;
}

export async function run(profileDir) {
  const id = 'SP12';
  if (!profileDir || !existsSync(profileDir)) {
    return skip(id, Severity.CRITICAL, '无 profile 目录，跳过 !!js 配置即代码检测');
  }

  const layers = collectPatchLayers(profileDir);
  const bundleHits = [];
  const userHits = [];
  const mitigatedHits = [];
  for (const { file, layer, pkg } of layers) {
    let text;
    try { text = readFileSync(file, 'utf8'); } catch { continue; }
    const hits = jsTagHits(text);
    if (!hits.length) continue;
    const sample = hits.slice(0, 3).map((h) => `行${h.line}: ${h.text}`).join('; ');
    if (layer === 'bundle') {
      // 逐处判定是否被用户层整值覆盖（config 整值替换 → __jsExpr 不入配置树 → 不求值）
      const active = [];
      const mitigated = [];
      for (const h of hits) {
        const rowId = rowIdFor(text, h.line);
        const by = isOverriddenByUserPatch(profileDir, rowId);
        (by ? mitigated : active).push({ ...h, rowId, by });
      }
      if (active.length) bundleHits.push(`${pkg || file}（${active.slice(0, 3).map((h) => `行${h.line}: ${h.text}`).join('; ')}）`);
      if (mitigated.length) mitigatedHits.push(`${pkg || file} — 行${mitigated[0].line} 的 id=${mitigated[0].rowId} 已被用户 patch 整值覆盖（${mitigated[0].by}）→ 表达式不会求值`);
    } else {
      userHits.push(`${file}（${sample}）`);
    }
  }

  const patchIssues = bundlePatchIssues(profileDir);

  if (bundleHits.length > 0 || patchIssues.length > 0) {
    const parts = [];
    if (bundleHits.length) {
      parts.push(`第三方 patch 使用 !!js 标签（**加载期执行任意 JavaScript**，#454/#587/#3354）：\n  ${bundleHits.join('\n  ')}`);
    }
    if (patchIssues.length) parts.push(`dsh.bundle.patch 路径异常：\n  ${patchIssues.join('\n  ')}`);
    return fail(id, Severity.CRITICAL,
      parts.join('\n')
      + (mitigatedHits.length ? `\n（另有 ${mitigatedHits.length} 处第三方 !!js 已被用户层整值覆盖，表达式不会求值：${mitigatedHits.join('；')}）` : '')
      + (userHits.length ? `\n（用户自有 patch 另有 !!js ${userHits.length} 处，属用户自主配置）` : ''),
      '要求该插件移除 !!js 标签（改用静态配置值）；若确需动态配置，应由用户在自己的 profile patch 里写。'
      + '同时修正 dsh.bundle.patch 指向，使其存在于包内',
      ['#454', '#587', '#3354']
    );
  }

  if (mitigatedHits.length) {
    // 有第三方 !!js，但已被用户层静态值覆盖：风险已消除，仍如实列出（visibility），但不判失败
    return pass(id, Severity.CRITICAL,
      `第三方 patch 含 !!js，但相关行已被用户层整值覆盖，表达式不会求值：\n  ${mitigatedHits.join('\n  ')}`
      + (userHits.length ? `\n（用户自有 patch 另有 !!js ${userHits.length} 处，属自主配置）` : '')
      + '\n注意：bundle 文件本身仍含 !!js，插件升级后请复核本覆盖是否仍然有效');
  }

  const note = userHits.length ? `；用户自有 patch 含 ${userHits.length} 处 !!js（用户自主配置，仅提示）` : '';
  return pass(id, Severity.CRITICAL,
    `扫描 ${layers.length} 个 patch 层：第三方层无 !!js 标签；${patchIssues.length === 0 ? 'dsh.bundle.patch 路径均健全' : ''}${note}`);
}

export const sp12Check = {
  id: 'SP12',
  name: 'config-as-code-tag',
  severity: Severity.CRITICAL,
  phase: CheckPhase.POST_INSTALL,
  description: '!!js 配置即代码（加载期执行 JS，实测宿主 RCE 面）+ dsh.bundle.patch 路径健全性（#454/#587/#3354）',
  src: 'builtin',
  runner: (profileDir) => run(profileDir),
};

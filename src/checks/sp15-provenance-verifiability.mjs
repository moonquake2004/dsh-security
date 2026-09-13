/**
 * SP15: Provenance verifiability —— 已装依赖的来源是否可验证
 *
 * 背景（生态审计 G5）：DSH 插件常以 `github:`、`file:`、直接 tarball URL 的方式安装。
 * 这类依赖**绕过 registry 的完整性校验与溯源（provenance）**：npm 不校验其内容哈希、
 * 无法核对发布者、也不会因上游改内容而报警。本机实测的典型后果就在眼前——
 * `dsh-at-file` 以固定 commit 的 tarball 安装，上游 0.7.0 修掉了已移除的 API，
 * 但用户停在 0.6.8 且**没有任何机制提示"你装的是不可验证来源"**。
 *
 * 本检查回答一个问题：**当前 profile 里，有多少依赖是"能核对"的？**
 *   - registry 依赖（含 integrity）→ 可验证
 *   - git/tarball/file/workspace 依赖 → 不可验证来源（逐条列出，并指出锁定方式）
 *
 * 分级：不可验证来源本身**不是漏洞**（很多插件只有源码分发），
 * 故默认 pass 并把清单写进 detail；仅当"不可验证 + 无版本锁定（无 commit/tag 固定）"
 * 时给出 HIGH —— 那意味着内容可被上游随时替换而你无从察觉。
 *
 * Severity: MEDIUM  Phase: LIFECYCLE
 */

import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail, skip } from '../protocol/check.mjs';

/** 判断一个 version spec 的来源类型 */
export function classifySpec(spec) {
  const s = String(spec ?? '');
  if (!s) return { kind: 'unknown', verifiable: false };
  if (/^https?:\/\//i.test(s)) {
    // GitHub codeload tar.gz + 40 位 sha = 内容锁定（比裸 latest 好，但仍不可核对发布者）
    const pinned = /[0-9a-f]{40}/i.test(s) || /\/tar\.gz\/v?\d+\.\d+\.\d+/.test(s);
    return { kind: 'tarball-url', verifiable: false, pinned };
  }
  if (/^(github|gitlab|bitbucket|gist):/i.test(s)) {
    const pinned = /#[0-9a-f]{7,40}$/i.test(s);
    return { kind: 'git-host', verifiable: false, pinned };
  }
  if (/^git\+/i.test(s) || /\.git(#|$)/i.test(s)) {
    const pinned = /#[0-9a-f]{7,40}$/i.test(s);
    return { kind: 'git-url', verifiable: false, pinned };
  }
  if (/^(file|link|workspace|portal):/i.test(s)) return { kind: 'local-path', verifiable: false, pinned: true };
  if (/^(npm|registry):/i.test(s)) return { kind: 'registry-explicit', verifiable: true };
  return { kind: 'registry-range', verifiable: true };
}

/**
 * lockfile 是否已把该依赖固定到具体 commit / 内容哈希。
 * 这一步是本检查的**精度关键**：`github:user/repo` 在 package.json 里看起来"未锁定"，
 * 但 pnpm/npm 的 lockfile 通常会记录解析后的 commit —— 此时内容其实**是锁定的**。
 * 早期版本只看 package.json，会把这类情况误报成"上游可随时替换"，属夸大。
 */
export function lockfilePin(profileDir, name) {
  const candidates = ['pnpm-lock.yaml', 'package-lock.json', 'npm-shrinkwrap.json'];
  for (const f of candidates) {
    const full = join(profileDir, f);
    if (!existsSync(full)) continue;
    let text;
    try { text = readFileSync(full, 'utf8'); } catch { continue; }
    // 找 `<name>@<spec>` 形式，spec 里带 40/64 位十六进制即视为已固定
    const re = new RegExp(`(^|[\\s"'])${name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}@[^\\s"']*?([0-9a-f]{40}|[0-9a-f]{64})`, 'm');
    const m = re.exec(text);
    if (m) return { file: f, sha: m[2] };
  }
  return null;
}

export async function run(profileDir) {
  const id = 'SP15';
  if (!profileDir || !existsSync(profileDir)) {
    return skip(id, Severity.MEDIUM, '无 profile 目录，跳过来源可验证性检查');
  }
  const manifest = join(profileDir, 'package.json');
  if (!existsSync(manifest)) return skip(id, Severity.MEDIUM, 'profile 缺少 package.json，无法判定依赖来源');

  let pkg;
  try { pkg = JSON.parse(readFileSync(manifest, 'utf8')); } catch {
    return skip(id, Severity.MEDIUM, 'profile 的 package.json 无法解析，跳过来源可验证性检查');
  }

  const deps = { ...(pkg.dependencies ?? {}), ...(pkg.devDependencies ?? {}) };
  const entries = Object.entries(deps);
  if (!entries.length) return skip(id, Severity.MEDIUM, 'profile 未声明任何依赖，跳过来源可验证性检查');

  const unverifiable = [];
  for (const [name, spec] of entries) {
    const c = classifySpec(spec);
    if (!c.verifiable) unverifiable.push({ name, spec: String(spec), ...c });
  }

  if (unverifiable.length === 0) {
    return pass(id, Severity.MEDIUM, `全部 ${entries.length} 个依赖均来自 registry，可由 integrity / provenance 核对`);
  }

  // 声明未锁定 ≠ 真的没锁：查 lockfile 是否已固定到 commit / 内容哈希
  for (const u of unverifiable) {
    if (!u.pinned) {
      const pin = lockfilePin(profileDir, u.name);
      if (pin) { u.pinned = true; u.pinnedBy = `${pin.file}#${pin.sha.slice(0, 12)}`; }
    }
  }
  const unlocked = unverifiable.filter((u) => !u.pinned);
  const lines = unverifiable.slice(0, 10).map((u) =>
    `  ${u.name} — ${u.kind}（${u.pinned ? (u.pinnedBy ? `lockfile 已固定: ${u.pinnedBy}` : '已内容锁定') : '**未锁定**'}）: ${u.spec.length > 70 ? u.spec.slice(0, 67) + '…' : u.spec}`
  ).join('\n');
  const head = `${entries.length} 个依赖中 ${unverifiable.length} 个来自不可核对来源（registry 之外——npm 不校验其哈希与发布者）：\n${lines}`;

  if (unlocked.length > 0) {
    return fail(id, Severity.HIGH,
      head + `\n其中 ${unlocked.length} 个**既未在 package.json 固定、lockfile 里也查不到 commit**——上游可随时替换内容而你无从察觉：${unlocked.map((u) => u.name).join(', ')}`,
      '为 git/tarball 依赖固定到具体 commit 或 tag；或推动作者发布到 npm（registry 依赖可被 integrity 核对）',
      ['#2461']
    );
  }

  // 不可核对但已锁定：如实列出，不判失败（很多插件只有源码分发）
  return pass(id, Severity.MEDIUM,
    head + '\n（均已内容锁定，风险可控；但发布者身份仍不可核对）');
}

export const sp15Check = {
  id: 'SP15',
  name: 'provenance-verifiability',
  severity: Severity.MEDIUM,
  phase: CheckPhase.LIFECYCLE,
  description: '依赖来源可验证性：区分 registry（可核对 integrity/provenance）与 git/tarball/本地（不可核对，未锁定则 HIGH）',
  src: 'builtin',
  runner: (profileDir) => run(profileDir),
};

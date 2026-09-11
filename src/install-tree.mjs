/**
 * DSH Security Framework — 安装树 / profile 布局解析（SP5、SP9 共用）
 *
 * 背景（2026-09 上游兼容审计 R5/R7）：
 * 0.1.5 起 `$DSH_HOME/profiles/node_modules` 是 **dsh 自有的符号链接镜像**，
 * 由 `healProfilesModuleFallback`（dsh-app-boot）写成 CLI 安装闭包的镜像；
 * 而 `$DSH_HOME/profiles/<name>/node_modules` 是 pnpm 真实安装目录。
 * 两者语义完全相反，检查必须区分「符号链接镜像」与「真实目录副本」，
 * 因此这里集中解析：
 *   - 安装前缀（CLI 自身所在的 @deepseek-ai 目录）
 *   - profile 布局（DSH_HOME / 当前 profile 名）
 *   - 符号链接目标是否落在安装前缀内
 */

import { existsSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, isAbsolute, join, resolve, sep } from 'node:path';

/** 用 profile 目录内的解析器定位真实安装位置（可命中 profile 自身的 node_modules） */
function requireFrom(baseDir) {
  try { return createRequire(join(baseDir, '__dsh_security_probe__.js')); } catch { return null; }
}

/**
 * 解析 CLI 安装的 @deepseek-ai 目录（安装前缀）。
 * 顺序：显式参数 → 从 profileDir 解析 @deepseek-ai/dsh/package.json →
 *       npm_node_execpath → DSH_HOME 镜像 → 常见全局前缀。
 * @returns {string|null}
 */
export function resolveInstallPrefix(profileDir, explicit = undefined) {
  if (explicit) return explicit;

  const candidates = [];
  if (profileDir) {
    const req = requireFrom(profileDir);
    if (req) {
      try {
        // @deepseek-ai/dsh/package.json → <prefix>/@deepseek-ai/dsh/package.json
        candidates.push(dirname(dirname(req.resolve('@deepseek-ai/dsh/package.json'))));
      } catch { /* 不在该解析路径 */ }
      try {
        candidates.push(dirname(dirname(req.resolve('@deepseek-ai/dsh-base/package.json'))));
      } catch { /* 不在该解析路径 */ }
    }
  }
  if (process.env.npm_node_execpath) {
    // …/lib/node_modules/npm/bin/node-gyp-bin/… 或 …/lib/node_modules/npm/…
    const parts = process.env.npm_node_execpath.split(sep);
    const idx = parts.lastIndexOf('node_modules');
    if (idx > 0) candidates.push(join(parts.slice(0, idx).join(sep), 'node_modules', '@deepseek-ai'));
  }
  if (process.env.DSH_HOME) {
    for (const n of ['dsh', 'dsh-base']) {
      const p = join(process.env.DSH_HOME, 'profiles', 'node_modules', '@deepseek-ai', n);
      if (existsSync(join(p, 'package.json'))) candidates.push(dirname(p));
    }
  }
  for (const n of ['dsh', 'dsh-base']) {
    const p = join('/opt/homebrew/lib/node_modules/@deepseek-ai', n);
    if (existsSync(join(p, 'package.json'))) { candidates.push(dirname(p)); break; }
  }
  for (const n of ['dsh', 'dsh-base']) {
    const p = join('/usr/local/lib/node_modules/@deepseek-ai', n);
    if (existsSync(join(p, 'package.json'))) { candidates.push(dirname(p)); break; }
  }

  for (const c of candidates) if (c && existsSync(c)) return c;
  return null;
}

/**
 * profile 目录布局：DSH_HOME 与当前 profile 名。
 * 支持两种入参：`<dshHome>/profiles/<name>`（doctor 传入）与 `<dshHome>/profiles`（镜像根）。
 *
 * 注意：<dshHome> 会做 realpath 归一（macOS 下 `/var` → `/private/var`），
 * 因此由本函数拼出的路径可能与调用方传入的 profileDir **写法不同**（指向同一实体）。
 * 需要"把调用方路径也列进扫描范围"的检查，应自行把入参一并加入候选。
 * @returns {{dshHome: string|null, profilesDir: string|null, profileName: string|null}}
 */
export function resolveProfileLayout(profileDir) {
  let dir;
  try { dir = realpathSync(profileDir); } catch { dir = profileDir; }
  const parent = dirname(dir);
  if (parent.endsWith(`${sep}profiles`) || parent.endsWith('/profiles')) {
    // <dshHome>/profiles/<name> — 排除直接等于 profiles 的情况
    const name = dir.slice(parent.length + 1);
    if (name && name !== 'profiles') {
      return { dshHome: dirname(parent), profilesDir: parent, profileName: name };
    }
  }
  if (dir.endsWith(`${sep}profiles`) || dir.endsWith('/profiles')) {
    return { dshHome: dirname(dir), profilesDir: dir, profileName: null };
  }
  return { dshHome: null, profilesDir: null, profileName: null };
}

/**
 * 共享镜像目录 `<dshHome>/profiles/node_modules`。
 * 对 `<dshHome>/profiles/<name>` 入参返回其父级镜像；对 `<dshHome>/profiles`
 * 入参返回自身（该目录本身就是镜像根）。无法确定 DSH_HOME 时返回 null。
 */
export function resolveSharedMirrorDir(profileDir) {
  const { dshHome } = resolveProfileLayout(profileDir);
  if (!dshHome) return null;
  return join(dshHome, 'profiles', 'node_modules');
}

/** 符号链接的解析后目标（相对链接按链接所在目录解析）；断链也返回字面目标 */
export function resolveLinkTarget(linkPath, rawTarget) {
  const abs = isAbsolute(rawTarget) ? rawTarget : resolve(dirname(linkPath), rawTarget);
  try { return realpathSync(abs); } catch { return abs; }
}

/** 目标是否落在安装前缀内（前缀为 null 时按“无法判定”返回 null） */
export function isInsidePrefix(target, prefix) {
  if (!prefix) return null;
  // 两侧都先做 realpath 归一（macOS 的 /var → /private/var 等别名），
  // 否则显式注入的前缀与链接目标可能因路径别名而比较失败——那是误报，不是发现。
  const canon = (p) => {
    try { return realpathSync(p); } catch { return resolve(p); }
  };
  const norm = (p) => (p.endsWith(sep) ? p.slice(0, -1) : p);
  const t = norm(canon(target));
  const p = norm(canon(prefix));
  return t === p || t.startsWith(p + sep);
}

/** 从候选 node_modules 目录中解析某个包的 package.json（内部使用） */
function resolvePkgJson(nmDirs, pkgName) {
  for (const nm of nmDirs) {
    const pj = join(nm, pkgName, 'package.json');
    if (existsSync(pj)) return pj;
  }
  try {
    const req = requireFrom(nmDirs[0] ? dirname(nmDirs[0]) : process.cwd());
    if (req) return req.resolve(`${pkgName}/package.json`);
  } catch { /* fallthrough */ }
  return null;
}

/** 读取版本号（内部使用） */
function readVersion(pkgJsonPath) {
  if (!pkgJsonPath) return null;
  try { return JSON.parse(readFileSync(pkgJsonPath, 'utf8')).version || null; } catch { return null; }
}

/**
 * 解析 CLI 实际提供的核心运行时版本（installation closure / 镜像链路）。
 * 返回值同时给出解析路径，便于检查在 detail 中如实标注来源。
 */
export function resolveCoreVersions(profileDir) {
  const nmDirs = [
    join(profileDir, 'node_modules'),
    resolveSharedMirrorDir(profileDir) ? join(resolveSharedMirrorDir(profileDir)) : null,
    process.env.DSH_HOME ? join(process.env.DSH_HOME, 'profiles', 'node_modules') : null,
  ].filter(Boolean);

  const out = {};
  for (const name of ['@deepseek-ai/dsh', '@deepseek-ai/dsh-base', '@deepseek-ai/dsh-tools', '@deepseek-ai/dsh-session', '@deepseek-ai/dsh-agent-loop']) {
    const pj = resolvePkgJson(nmDirs, name);
    out[name] = { version: readVersion(pj), path: pj };
  }
  return out;
}

/** DSH_HOME：仅凭明确信号推断，绝不猜测用户家目录内容 */
export function resolveDshHome(profileDir) {
  const layout = resolveProfileLayout(profileDir);
  if (layout.dshHome) return layout.dshHome;
  if (process.env.DSH_HOME) return process.env.DSH_HOME;
  return null;
}

/* ================= semver ================= */

/**
 * 尽力从安装树里取到真正的 node-semver（CLI 依赖闭包里有它，7.x）。
 * 取不到时返回 null——调用方必须据此降级为「无法判定」，不得自行近似断言不兼容。
 */
export function resolveSemver(profileDir, cliRoots = []) {
  const bases = [];
  const mirror = profileDir ? resolveSharedMirrorDir(profileDir) : null;
  if (mirror) bases.push(join(mirror, '@deepseek-ai', 'dsh-base'));
  if (profileDir) bases.push(join(profileDir, 'node_modules', '@deepseek-ai', 'dsh-base'));
  for (const r of cliRoots) bases.push(join(r, 'node_modules', '@deepseek-ai', 'dsh-base'));
  for (const dir of [...bases, ...(profileDir ? [profileDir] : [])]) {
    const req = requireFrom(dir);
    if (!req) continue;
    try {
      const mod = req('semver');
      if (mod && typeof mod.satisfies === 'function') return { mod, from: dir };
    } catch { /* 继续找 */ }
  }
  return null;
}

const splitVer = (s) => String(s).trim().replace(/^v/, '').split('-')[0].split('.').map(n => Number(n) || 0);
const isPre = (s) => String(s).includes('-');

function cmpVer(a, b) {
  const A = splitVer(a), B = splitVer(b);
  for (let i = 0; i < 3; i++) if (A[i] !== B[i]) return A[i] < B[i] ? -1 : 1;
  const pa = isPre(a), pb = isPre(b);
  if (pa !== pb) return pa ? -1 : 1;
  if (pa && pb && a !== b) return a < b ? -1 : 1;
  return 0;
}

/**
 * 无 node-semver 时的保守近似：只覆盖 `=` / 比较符 / `~` / `^` + `||` 的字面子集。
 * @returns {boolean|null} null = 无法判定（绝不当成 false——那会凭空造出不兼容结论）
 */
export function approxSatisfies(v, range) {
  const V = String(v).trim();
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(V)) return null;
  let anyParseable = false;
  for (const alt of String(range).split('||').map(s => s.trim()).filter(Boolean)) {
    const m = /^(\^|~|>=|<=|>|<|=)?\s*(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)\s*$/.exec(alt);
    if (!m) continue;
    anyParseable = true;
    const op = m[1] || '=', B = m[2];
    let inBase = false;
    const [vA, vB, vC] = splitVer(V);
    if (op === '=') inBase = cmpVer(V, B) === 0;
    else if (op === '>=') inBase = cmpVer(V, B) >= 0;
    else if (op === '>') inBase = cmpVer(V, B) > 0;
    else if (op === '<=') inBase = cmpVer(V, B) <= 0;
    else if (op === '<') inBase = cmpVer(V, B) < 0;
    else if (op === '~') {
      const [bA, bB] = splitVer(B);
      inBase = vA === bA && vB === bB && cmpVer(V, B) >= 0;
    } else if (op === '^') {
      const [bA, bB, bC] = splitVer(B);
      if (bA > 0) inBase = vA === bA && cmpVer(V, B) >= 0;
      else if (bB > 0) inBase = vA === 0 && vB === bB && cmpVer(V, B) >= 0;
      else inBase = vA === 0 && vB === 0 && cmpVer(V, B) >= 0 && (vC === bC || V === B);
    }
    if (!inBase) continue;
    if (!isPre(V)) return true;
    // 预发布版本：只有与比较符里的预发布 base 同 [major,minor,patch] 才可判定
    if (isPre(B)) {
      const [bA, bB, bC] = splitVer(B);
      if (vA === bA && vB === bB && vC === bC) return true;
    }
    continue;
  }
  return anyParseable ? false : null;
}

/**
 * 判定 `version` 是否满足 `range`。
 * @returns {{satisfies: boolean|null, exact: boolean}} satisfies=null 表示无法判定
 */
export function checkRange(version, range, semverMod = null) {
  if (!version || !range) return { satisfies: null, exact: false };
  if (semverMod) {
    try {
      return { satisfies: Boolean(semverMod.satisfies(version, range, { includePrerelease: false })), exact: true };
    } catch { return { satisfies: null, exact: false }; }
  }
  return { satisfies: approxSatisfies(version, range), exact: false };
}

/**
 * 遍历 profile node_modules 中的候选包目录（含 scoped 包）。
 * 与 SP5/SP8/SP10 的既有语义一致：跳过隐藏目录与 .bin。
 * @returns {Array<{dir: string, name: string}>}
 */
export function listPackageDirs(nmDir) {
  const out = [];
  if (!existsSync(nmDir)) return out;
  let entries;
  try { entries = readdirSync(nmDir, { withFileTypes: true }); } catch { return out; }
  for (const entry of entries) {
    if (!entry.name || entry.name.startsWith('.') || entry.name === '.bin') continue;
    // 注意：pnpm 会为包建符号链接，这里必须按“可进入的目录”判断，不能只看 isDirectory()
    const isDirLike = entry.isDirectory() || entry.isSymbolicLink();
    if (!isDirLike) continue;
    if (entry.name.startsWith('@')) {
      const scopeDir = join(nmDir, entry.name);
      let pkgs = [];
      try { pkgs = readdirSync(scopeDir, { withFileTypes: true }); } catch { continue; }
      for (const pkg of pkgs) {
        if (!pkg.name || pkg.name.startsWith('.')) continue;
        if (!pkg.isDirectory() && !pkg.isSymbolicLink()) continue;
        out.push({ dir: join(scopeDir, pkg.name), name: `${entry.name}/${pkg.name}` });
      }
      continue;
    }
    out.push({ dir: join(nmDir, entry.name), name: entry.name });
  }
  return out;
}

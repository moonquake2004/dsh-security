/**
 * DSH Security Framework — dsh 宿主配置读取（SP5 用）
 *
 * SP5 需要报告**真实**的能力面，其中宿主侧两项是权威来源：
 *   1. `$DSH_HOME/settings.yaml` 的 `permission` 命名空间
 *      （schema 仅 `{ defaultPreset }`，见 dsh-permission-presets/lib/index.js:24,121）
 *   2. `@deepseek-ai/dsh-base/cordis.patch.yml` 的
 *      `sandbox-policy.config.mode` / `approval.config.policy` / `permission.config.presets`
 *      （dsh-base/cordis.patch.yml:204-242）
 * 二者都在 profile 之外，必须按模块回退锚点解析（`$DSH_HOME/profiles/node_modules`）。
 *
 * 这里只实现读取这两个文件所需的最小 YAML 子集解析（块式 `key:` / `key: value` / 缩进层级），
 * 不引入依赖；块级解析用于定位 `- id: <row>` 行及其 `config:` 子树。
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

/** 最小块扫描：<缩进, 文本> 列表，跳过空行与整行注释 */
function blockLines(text) {
  const info = [];
  const lines = String(text).split('\n');
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (!raw.trim() || /^\s*#/.test(raw)) continue;
    const indent = raw.match(/^[ \t]*/)[0].replace(/\t/g, '  ').length;
    info.push({ indent, text: raw.trim(), line: i + 1 });
  }
  return info;
}

/**
 * 取 `- id: <rowId>` 行开始的块（到下一条同级 `- id:` 为止），
 * 返回其配置子树文本（不含 id 行本身）。找不到返回 null。
 */
export function rowBlock(text, rowId) {
  const info = blockLines(text);
  const want = `id: ${rowId}`;
  let start = -1, end = info.length, rowIndent = 0;
  for (let i = 0; i < info.length; i++) {
    const s = info[i].text.replace(/^-\s*/, '');
    if (s === want || s === `${want} ` || s.startsWith(`${want} `)) {
      start = i; rowIndent = info[i].indent;
      break;
    }
  }
  if (start < 0) return null;
  const reId = /^-?\s*id:\s/;
  for (let j = start + 1; j < info.length; j++) {
    if (info[j].indent <= rowIndent && reId.test(info[j].text)) { end = j; break; }
  }
  return info.slice(start, end);
}

/**
 * 在一个行的块里取某个顶层键的子树。
 * @returns {Array<{indent:number,text:string,line:number}>|null}
 */
export function keyBlock(block, key) {
  if (!block) return null;
  const idx = block.findIndex(l => l.text.startsWith(`${key}:`));
  if (idx < 0) return null;
  const base = block[idx].indent;
  const out = [block[idx]];
  for (let j = idx + 1; j < block.length; j++) {
    if (block[j].indent <= base) break;
    out.push(block[j]);
  }
  return out;
}

/** 在块里取 `key: value` 的裸标量（含引号/`!!js` 表达式原样返回） */
export function scalarIn(block, key) {
  if (!block) return null;
  for (const l of block) {
    const m = new RegExp(`^${key}:\\s*(.*)$`).exec(l.text);
    if (m) return m[1].trim();
  }
  return null;
}

function unquote(v) {
  if (v === null || v === undefined) return null;
  const t = String(v).trim();
  if ((t.startsWith("'") && t.endsWith("'")) || (t.startsWith('"') && t.endsWith('"'))) return t.slice(1, -1);
  return t;
}

/**
 * 从 `!!js` 表达式里抽出字面量（`a ?? 'b'` / 三元 / 纯字面量）。
 * 只做字面量识别，**不求值**——求值会让检查本身变成代码执行面。
 * `decisive=true` 表示表达式无条件返回该字面量（无 env 读取 / 无三元）。
 * @returns {{literal: string|null, expression: string|null, decisive: boolean}|null}
 */
export function evalScalarLiteral(raw) {
  if (raw === null || raw === undefined) return null;
  const t = String(raw).trim();
  if (!t) return null;
  if (t.startsWith('!!js')) {
    const expression = t.replace(/^!!js\s*/, '').trim();
    const strings = [...expression.matchAll(/'([^']*)'|"([^"]*)"/g)].map(m => m[1] ?? m[2]).filter(s => s !== '');
    const hasEnv = /process\.env/.test(expression);
    const hasTernary = /\?/.test(expression) && /:/.test(expression);
    return {
      literal: strings.length > 0 ? strings[0] : null,
      expression,
      decisive: strings.length === 1 && !hasEnv && !hasTernary,
    };
  }
  return { literal: unquote(t), expression: null, decisive: !/process\.env/.test(t) };
}

/** 取文本顶层某个 key 的块 */
export function topLevelKeyBlock(text, key) {
  return keyBlock(blockLines(text), key);
}

/**
 * 读取 settings.yaml 的 `permission` 命名空间。
 * @returns {{present:boolean, defaultPreset:string|null, raw:string|null, file:string|null}}
 */
export function readPermissionSettings(dshHome) {
  const file = dshHome ? join(dshHome, 'settings.yaml') : null;
  if (!file || !existsSync(file)) return { present: false, defaultPreset: null, raw: null, file };
  let text;
  try { text = readFileSync(file, 'utf8'); } catch { return { present: false, defaultPreset: null, raw: null, file }; }
  const block = topLevelKeyBlock(text, 'permission');
  if (!block) return { present: false, defaultPreset: null, raw: null, file };
  const raw = scalarIn(block, 'defaultPreset');
  return { present: true, defaultPreset: unquote(raw), raw, file };
}

/**
 * 解析 dsh-base 的 cordis.patch.yml，取出真实的沙箱/审批/预设配置。
 * @returns {object|null} 文件不存在时 null
 */
export function readHostSandboxConfig(basePatchPath) {
  if (!basePatchPath || !existsSync(basePatchPath)) return null;
  let text;
  try { text = readFileSync(basePatchPath, 'utf8'); } catch { return null; }

  const policyBlock = rowBlock(text, 'sandbox-policy');
  const approvalBlock = rowBlock(text, 'approval');
  const permissionBlock = rowBlock(text, 'permission');
  const sandboxBlock = rowBlock(text, 'sandbox');

  const policyCfg = keyBlock(policyBlock, 'config');
  const approvalCfg = keyBlock(approvalBlock, 'config');
  const permissionCfg = keyBlock(permissionBlock, 'config');

  const presets = {};
  const presetsBlock = keyBlock(permissionCfg, 'presets');
  if (presetsBlock) {
    // 顶层 preset 名 = 缩进为 presets 直属子级的 key
    const presetsIndent = presetsBlock[0].indent;
    let current = null;
    for (const l of presetsBlock.slice(1)) {
      if (l.indent === presetsIndent + 2 && /^[A-Za-z0-9_-]+:\s*$/.test(l.text)) {
        current = l.text.slice(0, -1);
        presets[current] = {};
        continue;
      }
      if (current && l.indent > presetsIndent) {
        const m = /^([A-Za-z0-9_-]+):\s*(.*)$/.exec(l.text);
        if (m) presets[current][m[1]] = unquote(m[2]);
      }
    }
  }

  const modeRaw = scalarIn(policyCfg, 'mode');
  const approvalRaw = scalarIn(approvalCfg, 'policy');

  return {
    path: basePatchPath,
    sandboxMode: evalScalarLiteral(modeRaw),
    approvalPolicy: evalScalarLiteral(approvalRaw),
    sandboxService: scalarIn(sandboxBlock, 'name') ? unquote(scalarIn(sandboxBlock, 'name')) : null,
    presets,
    presetsRaw: presetsBlock ? 'present' : 'absent',
  };
}

/**
 * 在候选 node_modules / 包目录中定位 dsh-base 的 cordis.patch.yml。
 * 复用模块回退锚点语义：profile → 逐级父目录 → CLI 安装根。
 */
export function resolveBasePatch(profileDir, cliRoots = []) {
  const cands = [];
  let dir = profileDir;
  for (let i = 0; i < 6 && dir; i++) {
    cands.push(join(dir, 'node_modules', '@deepseek-ai', 'dsh-base', 'cordis.patch.yml'));
    const parent = dir.replace(/[/\\][^/\\]*$/, '');
    if (!parent || parent === dir) break;
    dir = parent;
  }
  for (const root of cliRoots) {
    cands.push(join(root, 'node_modules', '@deepseek-ai', 'dsh-base', 'cordis.patch.yml'));
    cands.push(join(root, 'cordis.patch.yml'));
  }
  for (const c of cands) {
    try { if (existsSync(c)) return c; } catch { /* 继续 */ }
  }
  return null;
}

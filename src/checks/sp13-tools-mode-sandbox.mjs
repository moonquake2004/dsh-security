/**
 * SP13: Tools Mode × Sandbox Mismatch — Code Mode 绕过文件效应沙箱
 *
 * 出处：#3245（Critical，在 rc.7 / rc.8 上被两人独立复现）——
 * 当解析后的 tools mode 为 `ptc` / `both`（即 Code Mode / PTC，
 * 模型只拿到 `run_code` + 生成的 SDK），而沙箱仍处于限制性模式
 * （`read-only` / `workspace-write`）时，`run_code` 路径把模型写的
 * 程序送进 worker 线程执行，**不经过 `ctx.sandbox.confine()`**：
 * 程序可 `import('node:fs')` / `child_process`，从而获得完整宿主
 * 文件与进程权限。操作者以为生效的沙箱对代码执行不适用。
 *
 * 本检查纯粹由**已解析配置**判定，近零误报：
 *   - tools mode 来源（后者覆盖前者）：
 *       1. host bundle 各层（profile `dsh.profile.bundles` 顺序）中的
 *          `- id: tools` 行 `config.mode`
 *       2. profile 自身 `cordis.patch.yml`
 *       3. `DSH_TOOLS_MODE` 环境变量（当某层写成
 *          `mode: !!js process.env.DSH_TOOLS_MODE` 时生效）
 *       4. 生效的 agent preset（`settings.yaml` 的 `agent-presets.default`）
 *          的 `tool-presentation.config.mode` —— 这是 per-agent 开启 PTC
 *          的第二条路径（presets/ptc/agent.cordis.yml）
 *   - sandbox mode 来源（后者覆盖前者）：
 *       1. 各层的 `- id: sandbox-policy` 行 `config.mode`
 *       2. `DSH_PERMISSION_MODE` 环境变量（同上）
 *       3. `settings.yaml` 的 `permission.defaultPreset` → 映射到
 *          `permission.config.presets.<name>.sandbox`（新会话首帧即生效）
 *
 * 已核实的真实配置键（2026-09，dsh 0.1.5-alpha.1 安装树）：
 *   - `dsh-tools/lib/index.js:2570-2574`：`Config.mode` ∈
 *     {native, ptc, both}，`.default("native")`
 *   - `dsh-base/cordis.patch.yml:461-463`：`- id: tools`，不带 config
 *   - `dsh-web-app/cordis.patch.yml:34-38`：`- id: tools / config: mode:
 *     !!js process.env.DSH_TOOLS_MODE`（headless 同款在 :16）
 *   - `dsh-base/cordis.patch.yml:208-211`：`- id: sandbox-policy /
 *     config.mode: !!js process.env.DSH_PERMISSION_MODE ?? 'workspace-write'`
 *   - `dsh-base/cordis.patch.yml:229-242`：`- id: permission / config.presets`
 *   - `dsh-permission-presets/lib/index.js:24`：settings 命名空间 `permission`，
 *     schema 仅 `{ defaultPreset }`；`:293-305` 新会话按 defaultPreset 调
 *     `setSandboxMode`
 *   - `dsh-agent-tool-presentation/lib/index.js:31-47`：per-agent `mode`
 *   - `dsh-agent-presets/presets/ptc/agent.cordis.yml:270-272`：
 *     `- id: tool-presentation / config.mode: ptc`
 *
 * Severity: CRITICAL（默认策略下的静默逃逸；#3245 评分 9.8-10.0）
 * Phase: POST_INSTALL
 */

import { readFileSync, existsSync, realpathSync } from 'node:fs';
import { join, dirname, resolve as resolvePath } from 'node:path';
import { homedir } from 'node:os';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail, skip } from '../protocol/check.mjs';

const ID = 'SP13';

/** `dsh-tools` 接受的 mode（lib/index.js:2570-2574） */
const TOOLS_MODES = new Set(['native', 'ptc', 'both']);
/** 开启 Code Mode（run_code 传输）的值 */
const CODE_MODES = new Set(['ptc', 'both']);
/** `dsh-sandbox-policy` 接受的 mode */
const SANDBOX_MODES = new Set(['read-only', 'workspace-write', 'danger-full-access']);
/** 限制性沙箱 —— Code Mode 在其下即为逃逸 */
const RESTRICTIVE_SANDBOX = new Set(['read-only', 'workspace-write']);

/**
 * 内建 preset 表（dsh-base/cordis.patch.yml:229-242 已核实）。
 * 作为解析起点；任何层里出现的 presets 覆盖同名项。
 */
const BASE_PRESETS = Object.freeze({
  'read-only': { sandbox: 'read-only', approval: 'ask' },
  'workspace-write': { sandbox: 'workspace-write', approval: 'ask' },
  'danger-full-access': { sandbox: 'danger-full-access', approval: 'never' },
});

/* ────────────────────────── 极简 YAML 读取原语 ──────────────────────────
 * 项目零依赖（package.json engines 之外无 deps），且只需要读 patch 行里
 * 的少量标量，故用缩进感知的行解析而非引入 YAML 库。所有函数都只读。 */

function readText(p) {
  try { return readFileSync(p, 'utf8'); } catch { return null; }
}

function readJson(p) {
  const t = readText(p);
  if (t === null) return null;
  try { return JSON.parse(t); } catch { return null; }
}

function unquote(v) {
  const s = String(v).trim();
  if (s.length >= 2 && ((s.startsWith("'") && s.endsWith("'")) || (s.startsWith('"') && s.endsWith('"')))) {
    return s.slice(1, -1);
  }
  return s;
}

function escapeRe(s) { return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

/**
 * 取 patch 内容中 `- id: <rowId>` 这一项的文本块（到同/更浅缩进的下一个
 * `- ` 项为止）。找不到返回 null。
 */
function rowBlock(content, rowId) {
  const re = new RegExp(`^([ \\t]*)-[ \\t]*id:[ \\t]*['"]?${escapeRe(rowId)}['"]?[ \\t]*$`, 'm');
  const m = re.exec(content);
  if (!m) return null;
  const indent = m[1].length;
  const after = content.slice(m.index + m[0].length);
  let end = after.length;
  let offset = 0;
  for (const line of after.split('\n')) {
    const lm = /^([ \t]*)-[ \t]+\S/.exec(line);
    if (lm && lm[1].length <= indent) { end = offset; break; }
    offset += line.length + 1;
  }
  return after.slice(0, end);
}

/**
 * 取块内的 `config:` 段（到缩进 <= config 键的那一行为止）。
 * 返回 { text, indent } 或 null。
 */
function configSection(block) {
  const m = /^([ \t]*)config:[ \t]*$/m.exec(block);
  if (!m) return null;
  const indent = m[1].length;
  const after = block.slice(m.index + m[0].length);
  const out = [];
  for (const line of after.split('\n')) {
    if (line.trim() === '') { out.push(line); continue; }
    const lm = /^([ \t]*)\S/.exec(line);
    if (lm && lm[1].length <= indent) break;
    out.push(line);
  }
  return { text: out.join('\n'), indent };
}

/** 取段内某个子映射（如 config 下的 `presets:`）的文本块。 */
function subSection(section, key) {
  const lines = section.text.split('\n');
  let idx = -1;
  let indent = -1;
  for (let i = 0; i < lines.length; i++) {
    const m = /^([ \t]*)([A-Za-z0-9_.-]+):[ \t]*$/.exec(lines[i]);
    if (m && m[2] === key && m[1].length > section.indent) { idx = i; indent = m[1].length; break; }
  }
  if (idx < 0) return null;
  const out = [];
  for (let i = idx + 1; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim() === '') { out.push(line); continue; }
    const lm = /^([ \t]*)\S/.exec(line);
    if (lm && lm[1].length <= indent) break;
    out.push(line);
  }
  return { text: out.join('\n'), indent };
}

/**
 * 取段内直接子键的标量原文（缩进必须比段本身深）。找不到返回 undefined。
 */
function scalarAt(section, key) {
  for (const line of section.text.split('\n')) {
    const m = /^([ \t]*)([A-Za-z0-9_.-]+):[ \t]*(.*)$/.exec(line);
    if (!m) continue;
    if (m[2] !== key) continue;
    if (m[1].length <= section.indent) continue;
    return m[3].trim();
  }
  return undefined;
}

/**
 * 求值一个标量原文。返回 { known, value, envUnset }：
 *   - 纯字面量 → value = 去引号后的字符串
 *   - `!!js process.env.NAME`（可带 `?? 'default'` / `|| 'default'`）→
 *     环境变量有值则用之，否则用 fallback；无 fallback 时 value = undefined
 *     （由调用方套 schema 默认值）并记录 envUnset
 *   - 其它 `!!js` 表达式 / 块标量 → known=false（不猜）
 */
function evalScalar(raw, env) {
  if (raw === undefined) return { known: true, value: undefined };
  const v = String(raw).trim();
  if (v === '' || v === '>' || v === '>-' || v === '>' + '+' || v === '|' || v === '|-' || v === '|+') {
    return { known: false, reason: '块标量，静态不可解析' };
  }
  if (v.startsWith('!!js')) {
    const expr = v.replace(/^!!js\s+/, '').trim();
    const m = /^process\.env\.([A-Za-z_][A-Za-z0-9_]*)(?:\s*(?:\?\?|\|\|)\s*(['"])(.*?)\2)?$/.exec(expr);
    if (!m) return { known: false, reason: `非静态可解析的 !!js 表达式: ${expr}` };
    const envVal = env[m[1]];
    if (typeof envVal === 'string' && envVal.length > 0) return { known: true, value: envVal, envName: m[1] };
    if (m[2] !== undefined) return { known: true, value: m[3], envName: m[1], envFellBack: true };
    return { known: true, value: undefined, envName: m[1], envUnset: true };
  }
  if (v.startsWith('!!')) return { known: false, reason: `不支持的 YAML tag: ${v.slice(0, 16)}` };
  return { known: true, value: unquote(v) };
}

/* ────────────────────────── 配置定位 ────────────────────────── */

/** 从 profileDir 推断 DSH_HOME（`<home>/profiles/<name>` → `<home>`）。 */
function inferDshHome(profileDir, env) {
  if (env.DSH_HOME) return env.DSH_HOME;
  const resolved = resolvePath(profileDir);
  const m = /^(.*)[\\/]profiles[\\/][^\\/]+$/.exec(resolved);
  if (m && m[1]) return m[1];
  return join(homedir(), '.dsh');
}

/** 从 PATH 里的 `dsh` 反查 CLI 安装根（`<root>/node_modules/@deepseek-ai/dsh`）。 */
function resolveCliRoots(env) {
  const roots = [];
  const push = (p) => { if (p && !roots.includes(p)) roots.push(p); };
  if (env.DSH_CLI_ROOT) push(env.DSH_CLI_ROOT);
  for (const dir of String(env.PATH || '').split(':')) {
    if (!dir) continue;
    const bin = join(dir, 'dsh');
    try {
      if (!existsSync(bin)) continue;
      const real = realpathSync(bin); // .../@deepseek-ai/dsh/lib/bin.js
      push(dirname(dirname(real)));   // .../@deepseek-ai/dsh
    } catch { /* 非实际文件 / 权限问题 → 跳过 */ }
  }
  return roots;
}

/** 解析一个 bundle 包目录：profile 自身 → 逐级父目录的 node_modules → CLI 根。 */
function resolveBundleDir(name, profileDir, cliRoots) {
  const cands = [join(profileDir, 'node_modules', name)];
  let dir = resolvePath(profileDir);
  for (let i = 0; i < 8; i++) {
    const parent = dirname(dir);
    if (parent === dir) break;
    cands.push(join(parent, 'node_modules', name));
    dir = parent;
  }
  for (const root of cliRoots) {
    cands.push(join(root, 'node_modules', name));
    cands.push(join(root, name));
  }
  for (const c of cands) {
    try { if (existsSync(c)) return c; } catch { /* 跳过 */ }
  }
  return null;
}

/**
 * 按 profile 声明的 bundle 顺序收集所有 patch 层，最后追加 profile 自身
 * 的 cordis.patch.yml（用户 patch 最后应用）。
 */
function collectLayers(profileDir, cliRoots) {
  const layers = [];
  const pkg = readJson(join(profileDir, 'package.json'));
  const bundles = pkg && pkg.dsh && pkg.dsh.profile && Array.isArray(pkg.dsh.profile.bundles)
    ? pkg.dsh.profile.bundles
    : null;
  if (bundles) {
    for (const name of bundles) {
      if (typeof name !== 'string') continue;
      const dir = resolveBundleDir(name, profileDir, cliRoots);
      if (!dir) continue;
      const patchPath = join(dir, 'cordis.patch.yml');
      const content = readText(patchPath);
      if (content !== null) layers.push({ name, path: patchPath, content });
    }
  }
  const profilePatch = join(profileDir, 'cordis.patch.yml');
  const profileContent = readText(profilePatch);
  if (profileContent !== null) layers.push({ name: '(profile cordis.patch.yml)', path: profilePatch, content: profileContent });
  return { layers, declaredBundles: bundles };
}

/**
 * 解析某个行 id 的生效标量（如 tools.config.mode）。
 * 语义对齐 patch：后层覆盖前层；某层给了 `config:` 就整体替换，
 * 其中缺少该键即回到 schema 默认值。
 */
function resolveRow(layers, rowId, env, schemaDefault) {
  let found = false;
  let configRaw = undefined;
  let configLayer = null;
  let configSeen = false;
  let disabled = false;
  let disabledLayer = null;

  for (const layer of layers) {
    const block = rowBlock(layer.content, rowId);
    if (block === null) continue;
    found = true;
    const dm = /^[ \t]+disabled:[ \t]*(\S+)[ \t]*$/m.exec(block);
    if (dm) {
      if (dm[1] === 'true') { disabled = true; disabledLayer = layer; }
      else if (dm[1] === 'false') { disabled = false; disabledLayer = null; }
      // !!js 条件的 disabled → 无法静态判定，保持原状（不据此判安全）
    }
    const cfg = configSection(block);
    if (cfg) {
      configSeen = true;
      configRaw = scalarAt(cfg, 'mode');
      configLayer = layer;
    }
  }

  if (!found) return { status: 'missing' };
  if (disabled) return { status: 'disabled', layer: disabledLayer };

  const ev = evalScalar(configRaw, env);
  if (!ev.known) return { status: 'unknown', raw: configRaw, layer: configLayer, reason: ev.reason };

  let value = ev.value;
  let source = configLayer;
  let fromSchemaDefault = false;
  if (value === undefined) {
    value = schemaDefault;
    fromSchemaDefault = true;
  }
  return {
    status: 'value',
    value,
    raw: configRaw,
    layer: source,
    configSeen,
    fromSchemaDefault,
    envName: ev.envName,
    envFellBack: ev.envFellBack,
    envUnset: ev.envUnset,
  };
}

/** 收集权限 preset 表（内建表起步，各层 permission.config.presets 覆盖）。 */
function resolvePresets(layers) {
  const presets = {};
  for (const [k, v] of Object.entries(BASE_PRESETS)) presets[k] = { ...v };
  for (const layer of layers) {
    const block = rowBlock(layer.content, 'permission');
    if (block === null) continue;
    const cfg = configSection(block);
    if (!cfg) continue;
    const ps = subSection(cfg, 'presets');
    if (!ps) continue;
    const lines = ps.text.split('\n');
    let current = null;
    let entryIndent = -1;
    for (const line of lines) {
      const m = /^([ \t]*)([A-Za-z0-9_.-]+):[ \t]*(.*)$/.exec(line);
      if (!m) continue;
      const ind = m[1].length;
      if (ind <= ps.indent) continue;
      if (entryIndent === -1) entryIndent = ind;
      if (ind === entryIndent) {
        current = unquote(m[2]);
        if (!presets[current]) presets[current] = {};
        continue;
      }
      if (current && ind > entryIndent && m[2] === 'sandbox') presets[current].sandbox = unquote(m[3]);
    }
  }
  return presets;
}

/** 读 `<dshHome>/settings.yaml` 的命名空间段（只取两层，够用）。 */
function readSettings(dshHome) {
  for (const name of ['settings.yaml', 'settings.yml', 'settings.json']) {
    const p = join(dshHome, name);
    const text = readText(p);
    if (text === null) continue;
    if (name.endsWith('.json')) {
      const j = (() => { try { return JSON.parse(text); } catch { return null; } })();
      if (j && typeof j === 'object') return { path: p, sections: j };
      continue;
    }
    const sections = {};
    let current = null;
    for (const line of text.split('\n')) {
      if (line.trim() === '' || /^\s*#/.test(line)) continue;
      const top = /^([A-Za-z0-9_.-]+):[ \t]*(.*)$/.exec(line);
      if (top) {
        current = top[1];
        if (!sections[current] || typeof sections[current] !== 'object') sections[current] = {};
        if (top[2].trim() !== '') sections[current].__value = unquote(top[2]);
        continue;
      }
      const sub = /^[ \t]+([A-Za-z0-9_.-]+):[ \t]*(.*)$/.exec(line);
      if (sub && current && sections[current] && typeof sections[current] === 'object') {
        sections[current][sub[1]] = unquote(sub[2]);
      }
    }
    return { path: p, sections };
  }
  return { path: null, sections: {} };
}

/**
 * 解析生效 agent preset 的 per-agent tools presentation。
 * 返回 { known, value, source, reason }。
 */
function resolveAgentPresetMode(settings, layers, profileDir, dshHome, cliRoots, env) {
  let presetId = settings.sections['agent-presets'] && settings.sections['agent-presets'].default;
  let origin = presetId ? `${settings.path}: agent-presets.default=${presetId}` : null;

  if (!presetId) {
    for (const layer of layers) {
      const block = rowBlock(layer.content, 'agent-presets');
      if (block === null) continue;
      const cfg = configSection(block);
      if (!cfg) continue;
      const d = scalarAt(cfg, 'default');
      if (d !== undefined) {
        presetId = unquote(d);
        origin = `${layer.path}: agent-presets.config.default=${presetId}`;
      }
    }
  }
  if (!presetId) {
    return { known: false, reason: 'agent-presets 默认 preset 未配置（settings.yaml 与各层均无）' };
  }

  const candidates = [join(dshHome, '.agent-presets', presetId, 'agent.cordis.yml')];
  const apDir = resolveBundleDir('@deepseek-ai/dsh-agent-presets', profileDir, cliRoots);
  if (apDir) candidates.push(join(apDir, 'presets', presetId, 'agent.cordis.yml'));

  let file = null;
  for (const c of candidates) {
    if (readText(c) !== null) { file = c; break; }
  }
  if (file === null) {
    return { known: false, reason: `agent preset "${presetId}" 的组合文件 agent.cordis.yml 未找到（${origin}）` };
  }

  const content = readText(file);
  const block = rowBlock(content, 'tool-presentation');
  if (block === null) {
    return { known: true, value: 'native', source: `${file}: 无 tool-presentation 行 → native`, presetId, origin };
  }
  const cfg = configSection(block);
  const raw = cfg ? scalarAt(cfg, 'mode') : undefined;
  const ev = evalScalar(raw, env);
  if (!ev.known) {
    return { known: false, reason: `agent preset "${presetId}" 的 tool-presentation.config.mode 非静态可解析（${ev.reason}）` };
  }
  const value = ev.value === undefined ? 'native' : ev.value;
  if (!TOOLS_MODES.has(value)) {
    return { known: false, reason: `agent preset "${presetId}" 的 tool-presentation.config.mode="${value}" 不是已知取值` };
  }
  return { known: true, value, source: `${file}: tool-presentation.config.mode=${value}`, presetId, origin };
}

/** 把 provenance 渲染成人类可读的一句来源说明。 */
function describeValue(res, extra = '') {
  const bits = [];
  if (res.layer) bits.push(`来源 ${res.layer.path}${res.layer.name ? `（layer: ${res.layer.name}）` : ''}`);
  if (res.envName) {
    bits.push(res.envUnset
      ? `环境变量 ${res.envName} 未设置 → 落到 schema 默认值`
      : res.envFellBack
        ? `环境变量 ${res.envName} 未设置 → 落到表达式默认值`
        : `环境变量 ${res.envName}=${res.value}`);
  }
  if (res.fromSchemaDefault && !res.envName) bits.push('schema 默认值');
  if (extra) bits.push(extra);
  return bits.join('；');
}

/* ────────────────────────── 检查主体 ────────────────────────── */

/**
 * SP13 检查：Code Mode × 限制性沙箱错配（#3245）。
 * @param {string} profileDir - profile 目录（doctor 传入）
 * @param {{env?: object, dshHome?: string, cliRoots?: string[]}} [opts] - 测试注入点
 * @returns {Promise<import('../protocol/check.mjs').SecurityCheckResult>}
 */
export async function run(profileDir, opts = {}) {
  const env = opts.env ?? process.env;

  if (!profileDir || typeof profileDir !== 'string' || !existsSync(profileDir)) {
    return skip(ID, Severity.CRITICAL, `无法确定 profile 目录（收到 ${JSON.stringify(profileDir)}），跳过 Code Mode × 沙箱错配检查`);
  }

  const dshHome = opts.dshHome ?? inferDshHome(profileDir, env);
  const cliRoots = opts.cliRoots ?? resolveCliRoots(env);
  const { layers } = collectLayers(profileDir, cliRoots);

  if (layers.length === 0) {
    return skip(ID, Severity.CRITICAL,
      '未找到任何可读的 patch 层（profile package.json 的 dsh.profile.bundles 无法解析，profile 自身也无 cordis.patch.yml），无法确定 tools / sandbox mode');
  }

  const tools = resolveRow(layers, 'tools', env, 'native');
  const sandbox = resolveRow(layers, 'sandbox-policy', env, 'read-only');
  const presets = resolvePresets(layers);
  const settings = readSettings(dshHome);
  const agentPreset = resolveAgentPresetMode(settings, layers, profileDir, dshHome, cliRoots, env);

  /* ---- tools mode ---- */
  if (tools.status === 'missing') {
    return skip(ID, Severity.CRITICAL,
      `已扫描 ${layers.length} 个 patch 层，但没有任何一层声明 \`tools\` 行，无法确定 tools mode（不猜）`);
  }
  if (tools.status === 'unknown') {
    return skip(ID, Severity.CRITICAL,
      `\`tools\` 行的 config.mode 不是静态可解析的标量（${tools.reason}），无法确定 tools mode（不猜）`
      + (tools.layer ? `；来源 ${tools.layer.path}` : ''));
  }
  if (tools.status === 'disabled') {
    return pass(ID, Severity.CRITICAL,
      `\`tools\` 行被禁用（来源 ${tools.layer ? tools.layer.path : '?'}），进程内不存在 tools 注册表 → 无 Code Mode 执行面`);
  }
  if (!TOOLS_MODES.has(tools.value)) {
    return skip(ID, Severity.CRITICAL,
      `\`tools\` 行 config.mode="${tools.value}" 不在已知取值 {native, ptc, both} 内，无法确定 tools mode（不猜）`
      + (tools.layer ? `；来源 ${tools.layer.path}` : ''));
  }

  const deploymentCodeMode = CODE_MODES.has(tools.value);
  const agentCodeMode = agentPreset.known && CODE_MODES.has(agentPreset.value);

  /* ---- sandbox mode（含 settings.yaml permission.defaultPreset 覆盖）---- */
  let sandboxValue = null;
  let sandboxSource = '';

  if (sandbox.status === 'value') {
    if (!SANDBOX_MODES.has(sandbox.value)) {
      return skip(ID, Severity.CRITICAL,
        `\`sandbox-policy\` 行 config.mode="${sandbox.value}" 不在已知取值 {read-only, workspace-write, danger-full-access} 内，无法确定 sandbox mode（不猜）`
        + (sandbox.layer ? `；来源 ${sandbox.layer.path}` : ''));
    }
    sandboxValue = sandbox.value;
    sandboxSource = describeValue(sandbox);
  } else if (sandbox.status === 'unknown') {
    return skip(ID, Severity.CRITICAL,
      `\`sandbox-policy\` 行的 config.mode 不是静态可解析的标量（${sandbox.reason}），无法确定 sandbox mode（不猜）`
      + (sandbox.layer ? `；来源 ${sandbox.layer.path}` : ''));
  } else if (sandbox.status === 'disabled') {
    return skip(ID, Severity.CRITICAL,
      `\`sandbox-policy\` 行被禁用（来源 ${sandbox.layer ? sandbox.layer.path : '?'}），无法确定生效沙箱模式（不猜）`);
  } else {
    // missing：只有 settings.yaml 的 permission.defaultPreset 仍能给出答案
    sandboxValue = null;
  }

  const permRowPresent = layers.some((l) => rowBlock(l.content, 'permission') !== null);
  const presetSetting = settings.sections.permission && settings.sections.permission.defaultPreset;
  if (permRowPresent && presetSetting) {
    const spec = presets[presetSetting];
    if (!spec || !spec.sandbox || !SANDBOX_MODES.has(spec.sandbox)) {
      return skip(ID, Severity.CRITICAL,
        `settings.yaml permission.defaultPreset="${presetSetting}" 在 preset 表中没有可用的 sandbox 映射（已知：${Object.keys(presets).join(', ')}），无法确定 sandbox mode（不猜）`);
    }
    sandboxValue = spec.sandbox;
    sandboxSource = `${settings.path}: permission.defaultPreset=${presetSetting} → presets.${presetSetting}.sandbox=${spec.sandbox}`;
  }

  if (sandboxValue === null) {
    return skip(ID, Severity.CRITICAL,
      `已扫描 ${layers.length} 个 patch 层，但没有任何一层声明 \`sandbox-policy\` 行`
      + `（settings.yaml 也没有可用的 permission.defaultPreset），无法确定 sandbox mode（不猜）`);
  }

  /* ---- agent preset 面：部署层 native 时它才是决定项 ---- */
  if (!deploymentCodeMode && !agentPreset.known) {
    return skip(ID, Severity.CRITICAL,
      `tools mode = native 且 agent preset 的 presentation 无法确定（${agentPreset.reason}），无法排除 per-agent Code Mode（不猜）`);
  }

  const codeMode = deploymentCodeMode || agentCodeMode;
  const restrictive = RESTRICTIVE_SANDBOX.has(sandboxValue);

  const toolsLine = deploymentCodeMode
    ? `tools mode = "${tools.value}"（${describeValue(tools)}）`
    : agentCodeMode
      ? `tools mode = native（部署层），但 agent preset "${agentPreset.presetId}" 的 per-agent presentation = "${agentPreset.value}"（${agentPreset.source}）`
      : `tools mode = "${tools.value}"（${describeValue(tools)}${agentPreset.known ? `；agent preset "${agentPreset.presetId}" presentation = "${agentPreset.value}"` : ''}）`;
  const sandboxLine = `sandbox mode = "${sandboxValue}"（${sandboxSource}）`;

  if (!codeMode) {
    return pass(ID, Severity.CRITICAL,
      `Code Mode 未启用，无 #3245 错配：${toolsLine}；${sandboxLine}`);
  }

  if (!restrictive) {
    return pass(ID, Severity.CRITICAL,
      `Code Mode 已启用但沙箱为 danger-full-access，无沙箱可绕过（#3245 不适用）：${toolsLine}；${sandboxLine}`);
  }

  return fail(ID, Severity.CRITICAL,
    `Code Mode（PTC）在限制性沙箱下运行 —— run_code 绕过文件效应沙箱，模型代码获得完整宿主文件/进程权限（#3245，rc.7/rc.8 双重独立复现）：\n`
    + `  • ${toolsLine}\n`
    + `  • ${sandboxLine}\n`
    + `两个取值冲突：tools mode ∈ {ptc, both} 而 sandbox mode ∈ {read-only, workspace-write}。\n`
    + `run_code 的执行体是 worker 线程（@deepseek-ai/dsh-code-runtime-worker-thread），不经过 ctx.sandbox.confine()：`
    + `程序可 import('node:fs') / node:child_process，读写在沙箱外的宿主任意路径并启动进程；`
    + `操作者以为生效的文件效应沙箱对 Code Mode 不适用。`,
    '三选一：(1) 把 tools mode 切回 native —— 取消 DSH_TOOLS_MODE（或显式设为 native），并检查没有任何 agent preset 声明 tool-presentation.config.mode: ptc/both；'
    + '(2) 在知情前提下把沙箱显式设为 danger-full-access（DSH_PERMISSION_MODE=danger-full-access 或 settings.yaml permission.defaultPreset: danger-full-access），不再假装有沙箱；'
    + '(3) 换用可被沙箱约束的 code runtime（当前 worker-thread runtime 无 file-effect policy）',
    ['#3245']
  );
}

export const sp13Check = {
  id: 'SP13',
  name: 'tools-mode-sandbox-mismatch',
  severity: Severity.CRITICAL,
  phase: CheckPhase.POST_INSTALL,
  description: 'Code Mode（tools mode = ptc/both）× 限制性沙箱错配——run_code 绕过文件效应沙箱（#3245）',
  src: 'builtin',
  runner: (profileDir) => run(profileDir),
};

/** 测试用内部函数导出（非公开 API）。 */
export const __internal = {
  rowBlock,
  configSection,
  subSection,
  scalarAt,
  evalScalar,
  inferDshHome,
  resolveCliRoots,
  resolveBundleDir,
  collectLayers,
  resolveRow,
  resolvePresets,
  readSettings,
  resolveAgentPresetMode,
  TOOLS_MODES,
  CODE_MODES,
  SANDBOX_MODES,
  BASE_PRESETS,
};

/**
 * SP11: Patch-layer security-row override —— 第三方 patch 层静默改写安全配置
 *
 * 威胁（#587 / #4094）：Cordis patch 语义是"按 id 覆盖 + 后写获胜"，且**没有受保护行**。
 * 于是一个第三方 bundle 的 cordis.patch.yml 可以在 boot 时静默改写
 * sandbox / approval / permission 这类安全行（例如把 sandbox 模式放宽到 danger-full-access、
 * 把 approval 策略改成 never），而用户与既有检查都看不到——SP3/SP4 只做文本模式扫描，从不看**组合结果**。
 *
 * 本检查离线判定：把各层 patch 里触及安全行的条目找出来，并按**层来源**分级——
 *   - 第三方 bundle / profile 的 node_modules 内 → error（用户并未主动同意）
 *   - 用户自己的 profile patch → 只作提示（用户有权自己改）
 *
 * Severity: CRITICAL  Phase: POST_INSTALL
 */

import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail, skip } from '../protocol/check.mjs';

/** 安全行 id / 配置键：被改写即影响宿主安全姿态 */
const SECURITY_ROW_IDS = ['sandbox-policy', 'approval', 'permission'];
const SECURITY_KEYS = ['sandbox-policy', 'sandboxPolicy', 'approval', 'permission', 'defaultPreset', 'presets', 'policy'];

/** 收集各层 patch 文件，并标注来源层（bundle=第三方 / user=用户自有） */
export function collectPatchLayers(profileDir) {
  const layers = [];
  const userPatch = join(profileDir, 'cordis.patch.yml');
  if (existsSync(userPatch)) layers.push({ file: userPatch, layer: 'user' });

  const nmDir = join(profileDir, 'node_modules');
  if (existsSync(nmDir)) {
    let entries = [];
    try { entries = readdirSync(nmDir, { withFileTypes: true }); } catch { entries = []; }
    for (const entry of entries) {
      if (entry.name.startsWith('.')) continue;
      if (entry.name.startsWith('@')) {
        const scopeDir = join(nmDir, entry.name);
        let pkgs = [];
        try { pkgs = readdirSync(scopeDir, { withFileTypes: true }); } catch { continue; }
        for (const pkg of pkgs) {
          const f = join(scopeDir, pkg.name, 'cordis.patch.yml');
          if (existsSync(f)) layers.push({ file: f, layer: 'bundle', pkg: `${entry.name}/${pkg.name}` });
        }
      } else {
        const f = join(nmDir, entry.name, 'cordis.patch.yml');
        if (existsSync(f)) layers.push({ file: f, layer: 'bundle', pkg: entry.name });
      }
    }
  }
  return layers;
}

/**
 * 从 patch 文本里找出触及安全行的条目。
 * 采用保守的行扫描（不引入 YAML 依赖）：命中安全 id 或安全键即记录，并带上该行上下文。
 */
export function securityTouches(text) {
  const hits = [];
  const lines = text.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue; // 注释不算
    for (const id of SECURITY_ROW_IDS) {
      if (new RegExp(`(^|[-\\s'"])${id}(['"\\s:]|$)`).test(trimmed)) {
        hits.push({ line: i + 1, kind: 'row-id', value: id, text: trimmed.slice(0, 120) });
        break;
      }
    }
    for (const key of SECURITY_KEYS) {
      if (new RegExp(`^\\s*${key}\\s*:`).test(line) || new RegExp(`['"]?${key}['"]?\\s*:`).test(trimmed)) {
        if (!hits.some((h) => h.line === i + 1)) hits.push({ line: i + 1, kind: 'key', value: key, text: trimmed.slice(0, 120) });
        break;
      }
    }
  }
  return hits;
}

export async function run(profileDir) {
  const id = 'SP11';
  if (!profileDir || !existsSync(profileDir)) {
    return skip(id, Severity.CRITICAL, '无 profile 目录，跳过 patch 层安全行覆盖检测');
  }

  const layers = collectPatchLayers(profileDir);
  if (layers.length === 0) {
    return skip(id, Severity.CRITICAL, '未找到任何 cordis.patch.yml，无法判定 patch 层是否改写安全行');
  }

  const bundleHits = [];
  const userHits = [];
  for (const { file, layer, pkg } of layers) {
    let text;
    try { text = readFileSync(file, 'utf8'); } catch { continue; }
    const hits = securityTouches(text);
    if (hits.length === 0) continue;
    const sample = hits.slice(0, 3).map((h) => `行${h.line} ${h.value}: ${h.text}`).join('; ');
    if (layer === 'bundle') bundleHits.push(`${pkg || file}（${sample}）`);
    else userHits.push(`${file}（${hits.length} 处：${sample}）`);
  }

  if (bundleHits.length > 0) {
    return fail(id, Severity.CRITICAL,
      `第三方 patch 层改写了安全配置行（sandbox / approval / permission）——patch 按 id 覆盖且后写获胜，`
      + `宿主没有受保护行，因此这类改写会在 boot 时静默生效（#587/#4094）：\n  ${bundleHits.join('\n  ')}`
      + (userHits.length ? `\n（用户自有 patch 另有 ${userHits.length} 处，属用户自主配置）` : ''),
      '审查上述插件的 cordis.patch.yml，确认其修改安全行是必要的；如非必要，向作者反馈或移除该插件；'
      + '在宿主提供"受保护行"机制前，安全相关配置应只由用户层设置',
      ['#587', '#4094']
    );
  }

  if (userHits.length > 0) {
    return pass(id, Severity.CRITICAL,
      `安全行仅由用户自有 patch 触及（${userHits.length} 处），无第三方层改写：${userHits.join('; ')}`);
  }

  return pass(id, Severity.CRITICAL, `扫描 ${layers.length} 个 patch 层，无任何层改写 sandbox/approval/permission 安全行`);
}

export const sp11Check = {
  id: 'SP11',
  name: 'patch-security-override',
  severity: Severity.CRITICAL,
  phase: CheckPhase.POST_INSTALL,
  description: '第三方 patch 层静默改写安全配置行（sandbox/approval/permission）——patch 无受保护行（#587/#4094）',
  src: 'builtin',
  runner: (profileDir) => run(profileDir),
};

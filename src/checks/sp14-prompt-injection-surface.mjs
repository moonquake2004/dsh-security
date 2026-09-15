/**
 * SP14: Prompt-injection surface —— 插件注入内容里的提示注入面
 *
 * 背景：DSH 插件可以通过 `skills/**`、agent preset、以及 patch 里的说明字段，把**指令**直接
 * 送进模型的上下文。这类内容**不经过任何代码审查式的检查**（SP4 只看投毒关键词，SP10 只看
 * 混淆代码，P16/SP5 看的是导入与能力面），而它是 agent 生态的首要攻击面：一段被注入的指令
 * 可以让 agent 去做它在沙箱/审批下本不该做的事，且**没有代码可读**。
 *
 * 本检查扫"会被模型读到的文本"，按**证据强度分级**（照搬本项目最惨痛的教训：宁可少报也不要
 * 把操作者训练成忽略告警）：
 *
 *  A 级（fail，硬信号）
 *    1. **不可见/隐形 Unicode**：零宽字符、双向控制符、Unicode 标签字符——正常技能文本里
 *       不存在，几乎只有"对人隐藏、对模型可见"这一种用途；
 *    2. **凭据外泄指令**：指示读取凭据库/环境密钥并发送到外部（与 #6465 同类链条）；
 *    3. **静默执行指令**：明确要求"不要告诉用户/不要记录/不要请求批准"并伴随动作。
 *
 *  B 级（只计数，不产生发现）
 *    "忽略先前指令/你现在是…"这类**措辞**——在合法的安全技能里是正常的（例如教模型忽略
 *    不可信数据里的指令）。单独出现不足以判定，故仅计入 detail 提示。
 *
 * Severity: HIGH  Phase: POST_INSTALL
 */

import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail, skip } from '../protocol/check.mjs';

/** A1：不可见/隐形 Unicode（对人隐藏、对模型可见的经典手法） */
const INVISIBLE_UNICODE = [
  { name: 'zero-width', re: /[\u200B-\u200D\u2060\uFEFF]/ },
  { name: 'bidi override', re: /[\u202A-\u202E\u2066-\u2069]/ },
  { name: 'unicode tag chars', re: /[\u{E0000}-\u{E007F}]/u },
  { name: 'homoglyph space', re: /[\u00A0\u2000-\u200A\u202F\u205F\u3000]{3,}/ },
];

/**
 * A2：凭据外泄**指令**（读到密钥 → 发出去）。
 *
 * 注意（2026-09 实测教训）：早期写法只要求"密钥"与"http/send"在 120 字符内共现，
 * 结果把文档里的**配置示例**全报了出来（`"apiKey": "AIza...", "baseUrl": "https://…"`）。
 * 外泄是一段**指令**，必须同时具备「传输动词 + 密文对象 + 目的地/外发动作」，
 * 故这里要求动词在前、对象居中、目的地在后，三者缺一不可。
 */
const EXFIL_INSTRUCTION = [
  { name: 'send-secret-out', re: /\b(send|post|upload|transmit|exfiltrate|leak|forward|report)\b[\s\S]{0,80}\b(api[_-]?key|secret|token|password|credential|private key|\.env\b)\b[\s\S]{0,80}\b(to|into|https?:\/\/|webhook|remote|external|server)\b/i },
  { name: 'read-credentials-then-send', re: /\b(read|cat|open|load|access|copy)\b[\s\S]{0,60}\b(credentials?\.ya?ml|credentials?\.json|id_rsa|\.npmrc|\.env\b)\b[\s\S]{0,140}\b(send|post|upload|transmit|exfiltrate|curl|wget|https?:\/\/)\b/i },
];

/** A3：静默执行（要求不告知/不记录/不请求批准 + 动作） */
const SILENT_ACTION = [
  { name: 'do-not-tell-user', re: /(do not|don't|never)\s+(tell|inform|notify|mention|reveal)[\s\S]{0,40}(user|human|operator)/i },
  { name: 'without-asking', re: /without\s+(asking|approval|permission|confirmation|telling)[\s\S]{0,60}(run|execute|delete|write|install|send|modify)/i },
  { name: 'do-not-log', re: /(do not|don't|never)\s+(log|record|log this|leave a trace)/i },
];

/** B 级：措辞类（仅计数） */
const OVERRIDE_PHRASING = /(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|prompts?)/i;

/** 会被模型读到的文本文件 */
const PROMPT_TEXT_EXT = new Set(['.md', '.mdx', '.txt', '.yml', '.yaml']);
// 注意：路径分隔符必须同时接受 `/` 与 `\` —— Windows 上 path.join 产出反斜杠，
// 只写 `/` 会让本检查在 Windows 上一个文件都收集不到（整套检测形同虚设）。
// 2026-09 由 Windows CI 抓出（此前只有 ubuntu 一个环境）。
const PROMPT_DIR_HINT = /(^|[\\/])(skills?|prompts?|agents?|presets?|instructions?)([\\/]|$)/i;

/** 递归收集疑似"注入内容"的文件（限深、限量，避免扫描爆炸） */
export function collectPromptFiles(pkgDir, { maxFiles = 400, maxDepth = 4 } = {}) {
  const out = [];
  const walk = (dir, depth) => {
    if (out.length >= maxFiles || depth > maxDepth) return;
    let entries = [];
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (out.length >= maxFiles) return;
      if (e.name.startsWith('.') || e.name === 'node_modules') continue;
      const full = join(dir, e.name);
      if (e.isDirectory()) {
        // 只深入"疑似注入内容"的目录，或包的根（根下的 SKILL.md/README 也常被注入）
        if (PROMPT_DIR_HINT.test(full) || depth < 1) walk(full, depth + 1);
        continue;
      }
      if (!e.isFile()) continue;
      const ext = extname(e.name).toLowerCase();
      const isSkill = /^SKILL\.md$/i.test(e.name);
      if (isSkill || (PROMPT_TEXT_EXT.has(ext) && PROMPT_DIR_HINT.test(full))) {
        let size = 0; try { size = statSync(full).size; } catch { continue; }
        if (size > 0 && size < 512 * 1024) out.push(full);
      }
    }
  };
  walk(pkgDir, 0);
  return out;
}

export function scanPromptText(text) {
  const hard = [];
  for (const p of INVISIBLE_UNICODE) if (p.re.test(text)) hard.push({ kind: p.name, tier: 'invisible' });
  for (const p of EXFIL_INSTRUCTION) if (p.re.test(text)) hard.push({ kind: p.name, tier: 'exfil' });
  for (const p of SILENT_ACTION) if (p.re.test(text)) hard.push({ kind: p.name, tier: 'silent' });
  const soft = OVERRIDE_PHRASING.test(text);
  return { hard, soft };
}

/** 列出已装插件包目录（含 scoped） */
function listPackages(profileDir) {
  const nm = join(profileDir, 'node_modules');
  const out = [];
  if (!existsSync(nm)) return out;
  let entries = [];
  try { entries = readdirSync(nm, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (e.name.startsWith('.')) continue;
    if (e.name.startsWith('@')) {
      const scope = join(nm, e.name);
      let subs = [];
      try { subs = readdirSync(scope, { withFileTypes: true }); } catch { continue; }
      for (const s of subs) out.push({ name: `${e.name}/${s.name}`, dir: join(scope, s.name) });
    } else {
      out.push({ name: e.name, dir: join(nm, e.name) });
    }
  }
  return out;
}

export async function run(profileDir) {
  const id = 'SP14';
  if (!profileDir || !existsSync(profileDir)) {
    return skip(id, Severity.HIGH, '无 profile 目录，跳过提示注入面检测');
  }
  const pkgs = listPackages(profileDir);
  if (!pkgs.length) return skip(id, Severity.HIGH, 'profile 内无已装包，跳过提示注入面检测');

  const findings = [];
  let scannedFiles = 0;
  let softCount = 0;

  for (const pkg of pkgs) {
    for (const f of collectPromptFiles(pkg.dir)) {
      let text;
      try { text = readFileSync(f, 'utf8'); } catch { continue; }
      scannedFiles++;
      const { hard, soft } = scanPromptText(text);
      if (soft) softCount++;
      for (const h of hard) findings.push({ pkg: pkg.name, file: f, ...h });
    }
  }

  if (findings.length === 0) {
    return pass(id, Severity.HIGH,
      `扫描 ${pkgs.length} 个包、${scannedFiles} 个注入内容文件，未发现提示注入面`
      + (softCount ? `（另有 ${softCount} 个文件含"忽略先前指令"类措辞，属正常安全技能用语，未计入）` : ''));
  }

  // 去重（同包同类只列一次）+ 分级
  const seen = new Set();
  const listed = [];
  for (const f of findings) {
    const k = `${f.pkg}|${f.kind}`;
    if (seen.has(k)) continue;
    seen.add(k);
    listed.push(f);
  }
  const hasExfil = findings.some((f) => f.tier === 'exfil');
  const details = listed.slice(0, 10).map((f) =>
    `  ${f.pkg} — ${f.kind}${f.tier === 'invisible' ? '（不可见字符）' : f.tier === 'exfil' ? '（凭据外泄指令）' : '（静默执行指令）'}: ${f.file.split(/[\\/]node_modules[\\/]/).slice(1).join('/') || f.file}`
  ).join('\n');

  return fail(id, hasExfil ? Severity.CRITICAL : Severity.HIGH,
    `检测到 ${findings.length} 处提示注入面（涉及 ${new Set(findings.map((f) => f.pkg)).size} 个包）：\n${details}`,
    '逐一审查上述文件：不可见 Unicode 通常应完全删除；凭据外泄指令与静默执行指令必须移除。'
    + '若为合法安全技能（教模型忽略不可信数据里的指令），请在该处显式说明用途以便区分',
    ['#587', '#3354']
  );
}

export const sp14Check = {
  id: 'SP14',
  name: 'prompt-injection-surface',
  severity: Severity.HIGH,
  phase: CheckPhase.POST_INSTALL,
  description: '插件注入内容（skills/prompts/presets）里的提示注入面：不可见 Unicode、凭据外泄指令、静默执行指令',
  src: 'builtin',
  runner: (profileDir) => run(profileDir),
};

/**
 * dsh-ecosystem 集成
 *
 * 从 dsh-ecosystem 获取发布兼容性数据：
 * - 已知 bug 状态
 * - 发布兼容性报告
 * - 生态健康信号
 *
 * 复审修复：
 * - 旧实现 fetch raw.githubusercontent.com 的目录 URL——raw 不提供目录列表，必然 404，
 *   release-compat 半边永远拿不到数据；现改走 GitHub contents API 列目录并取最新文件。
 * - bug 雷达不再硬编码 weekly-2026-08-15.md，自动取 docs/ 下最新的 weekly-*.md。
 * - 数据源不可用返回 skip 而不是伪装通过。
 *
 * 复审修复（docs/ecosystem-audit-2026-09.md §2 EXT-ECO-1 / §3(c) / §4.4）——**加陈旧度护栏 + 杜绝静默降级**：
 *
 * 1. 陈旧度护栏。这是第三方数据源：不在 npm 上、无 license、单一维护者，周报随时可能停更。
 *    旧实现只要「拿得到内容且没有关键词命中」就判 pass —— 一份三个月前的周报同样会通过，
 *    读者无法区分「生态健康」与「数据源已经死了」。现在从文件名/正文解析数据源日期，
 *    最新数据源超过 STALE_AFTER_DAYS 天 → 显式 skip 并说明天数，绝不判 pass。
 *
 * 2. 命名/布局漂移 = skip。旧实现的 release-compat 文件名正则
 *    `/^release-compat-\d[\d-]*\.md$/` 与仓库实际布局不符（见 PICK_RELEASE_COMPAT 处的注释），
 *    于是那半边**每一轮都静默返回 null**，只靠周报半边给出 pass —— 典型的静默降级。
 *    现在：目录里找不到任何符合已知命名的文件 → 显式 skip（说明实际看到了什么文件名），
 *    而不是悄悄少查一半。
 *
 * 3. 缺一不可。两个数据源（release-compat 报告 + weekly 周报）任意一个读不到或认不出，
 *    都判 **skip + 原因**，而不是「用剩下那个给一个绿色」——半覆盖的 pass 与全没查在报告里看不出区别。
 *    只有两个数据源都新鲜可读时才给出 pass/fail，因此绿色必然意味着这次确实把两侧都查了。
 */

import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { skip, fail, pass } from '../protocol/check.mjs';

export const ECOSYSTEM_ID = 'EXT-ECO-1';

const REPO_DOCS_API = 'https://api.github.com/repos/zoahdev/dsh-ecosystem/contents/docs';
const RAW_BASE = 'https://raw.githubusercontent.com/zoahdev/dsh-ecosystem/main/docs';

/** 数据源陈旧阈值（天）。周报是周更，给 4 周余量；超过即认为数据源已停更。 */
export const STALE_AFTER_DAYS = 30;

const DAY_MS = 24 * 60 * 60 * 1000;

const GH_HEADERS = {
  'User-Agent': 'dsh-security',
  'Accept': 'application/vnd.github+json',
};

/** 数据源状态 */
const STATE = Object.freeze({
  OK: 'ok',                 // 取到了文档
  UNREACHABLE: 'unreachable', // 网络/API 失败，或取到空文档
  NO_FILE: 'no-file',       // 目录读到了，但没有符合已知命名的文件（契约/布局漂移）
});

async function ghFetch(fetchImpl, url, accept) {
  const response = await fetchImpl(url, {
    headers: { ...GH_HEADERS, ...(accept ? { Accept: accept } : {}) },
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) return null;
  return response;
}

/** 列 docs/<sub> 目录下的 .md 文件名（GitHub contents API），按名称倒序 */
async function listMarkdownFiles(fetchImpl, sub = '') {
  try {
    const response = await ghFetch(fetchImpl, sub ? `${REPO_DOCS_API}/${sub}` : REPO_DOCS_API);
    if (!response) return { ok: false, names: [] };
    const entries = await response.json();
    if (!Array.isArray(entries)) return { ok: false, names: [] };
    const names = entries
      .filter(e => e.type === 'file' && typeof e.name === 'string' && e.name.endsWith('.md'))
      .map(e => e.name)
      .sort()
      .reverse();
    return { ok: true, names };
  } catch {
    return { ok: false, names: [] };
  }
}

async function fetchRaw(fetchImpl, sub, name) {
  try {
    const response = await ghFetch(fetchImpl, `${RAW_BASE}/${sub ? sub + '/' : ''}${name}`);
    if (!response) return null;
    const text = await response.text();
    return typeof text === 'string' && text.trim() !== '' ? text : null;
  } catch { return null; }
}

/**
 * 从文件名里解析日期（weekly-2026-08-22.md → 2026-08-22Z）。
 * @param {string} name
 * @returns {Date|null}
 */
export function parseDateFromName(name) {
  const matched = /(\d{4})-(\d{2})-(\d{2})/.exec(String(name ?? ''));
  if (!matched) return null;
  const date = new Date(`${matched[1]}-${matched[2]}-${matched[3]}T00:00:00Z`);
  return Number.isNaN(date.getTime()) ? null : date;
}

/**
 * 数据源日期：优先文件名里的日期，其次正文里的生成时间
 * （release-compat 报告正文首部有 `Generated 2026-09-10T04:50:58.248Z`）。
 * @param {string} name
 * @param {string} text
 * @returns {Date|null}
 */
export function docDate(name, text) {
  const fromName = parseDateFromName(name);
  if (fromName) return fromName;
  const matched = /Generated\s+(\d{4})-(\d{2})-(\d{2})/i.exec(String(text ?? ''));
  if (!matched) return null;
  const date = new Date(`${matched[1]}-${matched[2]}-${matched[3]}T00:00:00Z`);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** 解析 `<major>.<minor>.<patch>[-prerelease].md` 形式的版本文件名 */
function parseVersionName(name) {
  const matched = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?\.md$/.exec(String(name ?? ''));
  if (!matched) return null;
  return { major: Number(matched[1]), minor: Number(matched[2]), patch: Number(matched[3]), pre: matched[4] ?? '' };
}

function compareVersionDesc(a, b) {
  if (a.major !== b.major) return b.major - a.major;
  if (a.minor !== b.minor) return b.minor - a.minor;
  if (a.patch !== b.patch) return b.patch - a.patch;
  // 预发布串：非空 > 空（rc 高于正式版内的同号）——这里按字符串倒序即可，命名空间很窄
  return String(b.pre).localeCompare(String(a.pre));
}

/**
 * 选最新的发布兼容性报告文件名。
 *
 * 实测布局（2026-09-11 经 GitHub contents API 核实）：`docs/release-compat/<version>.md`
 * （0.1.0-rc.6.md、0.1.5-rc.1.md …，正文首行为 `# Release compatibility report — 0.1.5-rc.1`）。
 * 审计报告记的是 `release-compat-<date>.md`，两种命名都接受：优先版本命名的（按版本序），
 * 其次才是旧的日期命名。都不匹配 → 返回 null，由调用方升级为带原因的 skip。
 */
export function pickReleaseCompatName(names) {
  const versioned = (names ?? [])
    .map(name => ({ name, version: parseVersionName(name) }))
    .filter(entry => entry.version)
    .sort((a, b) => compareVersionDesc(a.version, b.version));
  if (versioned.length > 0) return versioned[0].name;

  const legacy = (names ?? []).filter(name => /^release-compat-\d[\d-]*\.md$/.test(name)).sort().reverse();
  return legacy[0] ?? null;
}

/** 选最新的 bug 雷达周报文件名（weekly-YYYY-MM-DD.md） */
export function pickWeeklyName(names) {
  return (names ?? []).filter(name => /^weekly-\d{4}-\d{2}-\d{2}\.md$/.test(name)).sort().reverse()[0] ?? null;
}

/**
 * 取发布兼容性报告。
 * @returns {Promise<{label: string, state: string, name?: string, text?: string, detail?: string}>}
 */
async function fetchReleaseCompat(fetchImpl) {
  const label = 'release-compat';
  const listed = await listMarkdownFiles(fetchImpl, 'release-compat');
  if (!listed.ok) return { label, state: STATE.UNREACHABLE, detail: 'GitHub contents API 请求失败' };
  const name = pickReleaseCompatName(listed.names);
  if (!name) {
    return {
      label,
      state: STATE.NO_FILE,
      detail: `docs/release-compat/ 下没有符合 <version>.md 或 release-compat-<date>.md 的文件（实际：${listed.names.join('、') || '空目录'}）`,
    };
  }
  const text = await fetchRaw(fetchImpl, 'release-compat', name);
  if (!text) return { label, state: STATE.UNREACHABLE, name, detail: `raw 取 ${name} 失败或内容为空` };
  return { label, state: STATE.OK, name, text };
}

/**
 * 取最新一期 bug 雷达周报。
 * @returns {Promise<{label: string, state: string, name?: string, text?: string, detail?: string}>}
 */
async function fetchBugRadar(fetchImpl) {
  const label = 'bug-radar(weekly)';
  const listed = await listMarkdownFiles(fetchImpl, '');
  if (!listed.ok) return { label, state: STATE.UNREACHABLE, detail: 'GitHub contents API 请求失败' };
  const name = pickWeeklyName(listed.names);
  if (!name) {
    return {
      label,
      state: STATE.NO_FILE,
      detail: `docs/ 下没有 weekly-YYYY-MM-DD.md（实际 .md：${listed.names.join('、') || '空目录'}）`,
    };
  }
  const text = await fetchRaw(fetchImpl, '', name);
  if (!text) return { label, state: STATE.UNREACHABLE, name, detail: `raw 取 ${name} 失败或内容为空` };
  return { label, state: STATE.OK, name, text };
}

/**
 * 依据已取到的数据源给出结论（纯函数，便于单测）。
 *
 * @param {{release: object|null, radar: object|null, now?: Date}} input
 * @returns {import('../protocol/check.mjs').SecurityCheckResult}
 */
export function evaluateSources({ release, radar, now = new Date() }) {
  const sources = [release, radar].filter(Boolean);

  if (sources.length === 0) {
    return skip(ECOSYSTEM_ID, Severity.LOW, 'dsh-ecosystem 没有任何可用数据源，跳过生态兼容性检查');
  }

  // 两个数据源缺一不可：任何一个读不到（不可达）或认不出（命名/布局漂移），
  // 都是「这次没真正查完」→ 显式 skip 并逐条给出原因。
  // （旧实现只靠周报半边就给 pass：release-compat 的文件名正则与仓库实际布局不符，
  //   那半边每轮静默返回 null —— 少查一半却仍显示绿色，正是要消除的 false green。）
  const unavailable = sources.filter(s => s.state !== STATE.OK);
  if (unavailable.length > 0) {
    const reasons = unavailable.map(s => {
      const kind = s.state === STATE.NO_FILE ? '命名/布局与预期不符' : '数据源不可达';
      return `${s.label}（${kind}：${s.detail ?? '未知原因'}）`;
    }).join('；');
    return skip(ECOSYSTEM_ID, Severity.LOW,
      `dsh-ecosystem 无法完成生态兼容性检查：${reasons}；跳过（不外推为通过）`);
  }

  const docs = sources;

  // 陈旧度护栏：最新数据源太旧 → skip（不能拿一份停更许久的周报判 pass）
  const dated = docs
    .map(doc => ({ ...doc, date: docDate(doc.name, doc.text) }))
    .filter(doc => doc.date);
  if (dated.length === 0) {
    return skip(ECOSYSTEM_ID, Severity.LOW,
      `dsh-ecosystem 数据源中不含可解析日期（${docs.map(d => d.name).join('、')}），无法判断新鲜度，跳过生态兼容性检查`);
  }
  const newest = dated.reduce((a, b) => (a.date >= b.date ? a : b));
  const ageDays = Math.floor((now.getTime() - newest.date.getTime()) / DAY_MS);
  if (ageDays > STALE_AFTER_DAYS) {
    return skip(ECOSYSTEM_ID, Severity.LOW,
      `dsh-ecosystem 数据源陈旧：最新 ${newest.name} 生成于 ${newest.date.toISOString().slice(0, 10)}，距今 ${ageDays} 天（阈值 ${STALE_AFTER_DAYS} 天），跳过生态兼容性检查`);
  }

  const issues = [];

  // 检查是否有已知的 breaking changes
  const releaseDoc = docs.find(d => d.label === 'release-compat');
  if (releaseDoc) {
    const breakingMatch = releaseDoc.text.match(/breaking|incompatible|migration/gi);
    if (breakingMatch && breakingMatch.length > 0) {
      issues.push({ type: 'breaking-changes', detail: `${releaseDoc.name} 中发现 ${breakingMatch.length} 个 breaking change 提及` });
    }
  }

  // 检查是否有 critical bugs
  const radarDoc = docs.find(d => d.label === 'bug-radar(weekly)');
  if (radarDoc) {
    const criticalMatch = radarDoc.text.match(/critical|CRITICAL|严重/gi);
    if (criticalMatch && criticalMatch.length > 0) {
      issues.push({ type: 'critical-bugs', detail: `${radarDoc.name} 中发现 ${criticalMatch.length} 个 critical 级别问题` });
    }
  }

  const coverage = docs
    .map(doc => {
      const date = docDate(doc.name, doc.text);
      const age = date ? `${Math.max(0, Math.floor((now.getTime() - date.getTime()) / DAY_MS))} 天前` : '日期未知';
      return `${doc.name}（${age}）`;
    })
    .join('、');

  if (issues.length === 0) {
    const result = pass(ECOSYSTEM_ID, Severity.LOW,
      `dsh-ecosystem 生态兼容性检查通过（数据源：${coverage}）`);
    result.evidence = { sources: docs.map(d => d.name) };
    return result;
  }

  const details = issues.map(i => `${i.type}: ${i.detail}`).join('\n');
  const result = fail(
    ECOSYSTEM_ID,
    Severity.LOW,
    `dsh-ecosystem 检测到 ${issues.length} 个生态关注点：\n${details}`,
    '查看 dsh-ecosystem 周报获取最新生态状态',
  );
  result.evidence = { sources: docs.map(d => d.name), issues };
  return result;
}

/**
 * @param {string} profileDir - 未使用（生态检查与 profile 无关），保留以匹配 registry 的调用约定
 * @param {{fetchImpl?: typeof fetch, now?: Date}} [deps] - 测试注入点
 */
export async function runCheck(profileDir, deps = {}) {
  const fetchImpl = deps.fetchImpl ?? fetch;
  const [release, radar] = await Promise.all([
    fetchReleaseCompat(fetchImpl),
    fetchBugRadar(fetchImpl),
  ]);
  return evaluateSources({ release, radar, now: deps.now ?? new Date() });
}

export const ecosystemCheck = {
  id: ECOSYSTEM_ID,
  name: 'ecosystem-compat',
  severity: Severity.LOW,
  phase: CheckPhase.LIFECYCLE,
  description: 'dsh-ecosystem 生态兼容性检查',
  src: 'external',
  source: 'dsh-ecosystem',
  runner: (profileDir) => runCheck(profileDir),
};

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
 */

import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { skip } from '../protocol/check.mjs';

const REPO_DOCS_API = 'https://api.github.com/repos/zoahdev/dsh-ecosystem/contents/docs';
const RAW_BASE = 'https://raw.githubusercontent.com/zoahdev/dsh-ecosystem/main/docs';

const GH_HEADERS = {
  'User-Agent': 'dsh-security',
  'Accept': 'application/vnd.github+json',
};

async function ghFetch(url, accept) {
  const response = await fetch(url, {
    headers: { ...GH_HEADERS, ...(accept ? { Accept: accept } : {}) },
    signal: AbortSignal.timeout(10000),
  });
  if (!response.ok) return null;
  return response;
}

/** 列 docs/<sub> 目录下的 .md 文件名（GitHub contents API），按名称倒序 */
async function listMarkdownFiles(sub = '') {
  try {
    const response = await ghFetch(sub ? `${REPO_DOCS_API}/${sub}` : REPO_DOCS_API);
    if (!response || !response.ok) return null;
    const entries = await response.json();
    if (!Array.isArray(entries)) return null;
    return entries
      .filter(e => e.type === 'file' && e.name.endsWith('.md'))
      .map(e => e.name)
      .sort()
      .reverse();
  } catch { return null; }
}

async function fetchRaw(sub, name) {
  try {
    const response = await ghFetch(`${RAW_BASE}/${sub ? sub + '/' : ''}${name}`);
    if (!response || !response.ok) return null;
    return await response.text();
  } catch { return null; }
}

/**
 * 获取最新发布兼容性报告
 */
async function fetchReleaseCompat() {
  const names = await listMarkdownFiles('release-compat');
  if (!names || names.length === 0) return null;
  const latest = names.find(n => /^release-compat-\d[\d-]*\.md$/.test(n));
  if (!latest) return null;
  return fetchRaw('release-compat', latest);
}

/**
 * 获取最新一期 bug 雷达周报
 */
async function fetchBugRadar() {
  const names = await listMarkdownFiles('');
  if (!names) return null;
  const latest = names.find(n => /^weekly-\d{4}-\d{2}-\d{2}\.md$/.test(n));
  if (!latest) return null;
  return fetchRaw('', latest);
}

export async function runCheck(profileDir) {
  const id = 'EXT-ECO-1';

  const [releaseNotes, bugRadar] = await Promise.all([fetchReleaseCompat(), fetchBugRadar()]);

  if (!releaseNotes && !bugRadar) {
    return skip(id, Severity.LOW, 'dsh-ecosystem 数据源不可达（离线或仓库无数据），跳过生态兼容性检查');
  }

  const issues = [];

  // 检查是否有已知的 breaking changes
  if (releaseNotes) {
    const breakingMatch = releaseNotes.match(/breaking|incompatible|migration/gi);
    if (breakingMatch && breakingMatch.length > 0) {
      issues.push({ type: 'breaking-changes', detail: `发布兼容性报告中发现 ${breakingMatch.length} 个 breaking change 提及` });
    }
  }

  // 检查是否有 critical bugs
  if (bugRadar) {
    const criticalMatch = bugRadar.match(/critical|CRITICAL|严重/gi);
    if (criticalMatch && criticalMatch.length > 0) {
      issues.push({ type: 'critical-bugs', detail: `Bug 雷达中发现 ${criticalMatch.length} 个 critical 级别问题` });
    }
  }

  if (issues.length === 0) {
    return { id, ok: true, severity: Severity.LOW, detail: 'dsh-ecosystem 生态兼容性检查通过' };
  }

  const details = issues.map(i => `${i.type}: ${i.detail}`).join('\n');
  return {
    id,
    ok: false,
    severity: Severity.LOW,
    detail: `dsh-ecosystem 检测到 ${issues.length} 个生态关注点：\n${details}`,
    fix: '查看 dsh-ecosystem 周报获取最新生态状态',
  };
}

export const ecosystemCheck = {
  id: 'EXT-ECO-1',
  name: 'ecosystem-compat',
  severity: Severity.LOW,
  phase: CheckPhase.LIFECYCLE,
  description: 'dsh-ecosystem 生态兼容性检查',
  src: 'external',
  source: 'dsh-ecosystem',
  runner: (profileDir) => runCheck(profileDir),
};

/**
 * dsh-ecosystem 集成
 *
 * 从 dsh-ecosystem 获取发布兼容性数据：
 * - 已知 bug 状态
 * - 发布兼容性报告
 * - 生态健康信号
 */

import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';

const ECOSYSTEM_API = 'https://raw.githubusercontent.com/zoahdev/dsh-ecosystem/main/docs';

/**
 * 获取发布兼容性报告
 */
async function fetchReleaseCompat() {
  try {
    const response = await fetch(`${ECOSYSTEM_API}/release-compat/`, { signal: AbortSignal.timeout(10000) });
    if (!response.ok) return null;
    // 解析目录列表找最新的兼容性报告
    const text = await response.text();
    const match = text.match(/release-compat-[\d-]+\.md/);
    if (!match) return null;

    const reportResponse = await fetch(`${ECOSYSTEM_API}/release-compat/${match[0]}`, { signal: AbortSignal.timeout(10000) });
    if (!reportResponse.ok) return null;
    return await reportResponse.text();
  } catch { return null; }
}

/**
 * 获取 bug 雷达
 */
async function fetchBugRadar() {
  try {
    const response = await fetch(`${ECOSYSTEM_API}/weekly-2026-08-15.md`, { signal: AbortSignal.timeout(10000) });
    if (!response.ok) return null;
    return await response.text();
  } catch { return null; }
}

export async function runCheck(profileDir) {
  const id = 'EXT-ECO-1';

  const releaseNotes = await fetchReleaseCompat();
  const bugRadar = await fetchBugRadar();

  if (!releaseNotes && !bugRadar) {
    return { id, ok: true, severity: Severity.LOW, detail: 'dsh-ecosystem 数据源不可用，跳过生态兼容性检查' };
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

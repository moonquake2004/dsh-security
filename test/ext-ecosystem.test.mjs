/**
 * EXT-ECO-1: dsh-ecosystem 集成测试（陈旧度护栏 + 不静默降级）
 *
 * 形状来源（2026-09-11 经 GitHub contents API + raw 直读，非推测）：
 *   · `docs/weekly-YYYY-MM-DD.md`（当时最新 weekly-2026-08-22.md），正文含 "critical"/"严重" 等词。
 *   · `docs/release-compat/<version>.md`（当时 0.1.0-rc.6 … 0.1.5-rc.1），正文首行
 *     `# Release compatibility report — 0.1.5-rc.1`，含 `Generated 2026-09-10T04:50:58.248Z`。
 *     —— 注意：审计报告写的是 `release-compat-<date>.md`，实际目录里是版本命名；两种都支持，
 *        版本命名优先（不确定版本命名是否是长期约定，故同时保留旧模式并各写一条用例）。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  evaluateSources,
  runCheck,
  parseDateFromName,
  docDate,
  pickReleaseCompatName,
  pickWeeklyName,
  STALE_AFTER_DAYS,
} from '../src/integrations/ecosystem.mjs';

/** 与上游正文一致的片段（含 Generated 时间戳） */
const RELEASE_TEXT = `# Release compatibility report — 0.1.5-rc.1

> Generated 2026-09-10T04:50:58.248Z by dsh-ecosystem · sources: npm registry + GitHub Actions API

## npm dist-tags (@deepseek-ai/dsh)

| Tag | Version |
| --- | --- |
| \`latest\` | \`0.1.5-rc.1\` |
`;

const WEEKLY_TEXT = `# This week in dsh — 2026-08-22 (Week 2)

- 收录里程碑：两个 awesome 列表 PR 已合并 ✅
- 官方 release train：latest 已修到 0.1.0-rc.7
`;

const okRelease = { label: 'release-compat', state: 'ok', name: '0.1.5-rc.1.md', text: RELEASE_TEXT };
const okRadar = { label: 'bug-radar(weekly)', state: 'ok', name: 'weekly-2026-08-22.md', text: WEEKLY_TEXT };
const NOW = new Date('2026-09-11T00:00:00Z');

/** GitHub contents API 的真实文件清单（2026-09-11 快照） */
const REAL_RELEASE_COMPAT_NAMES = ['0.1.0-rc.6.md', '0.1.0-rc.7.md', '0.1.0-rc.8.md', '0.1.1-rc.2.md', '0.1.2-rc.1.md', '0.1.5-rc.1.md'];
const REAL_DOCS_NAMES = ['bug-families.md', 'ecosystem-supply-chain-health-2026-09-07.md', 'weekly-2026-08-15.md', 'weekly-2026-08-19.md', 'weekly-2026-08-22.md'];

const jsonResponse = (value) => ({ ok: true, status: 200, async json() { return value; }, async text() { return JSON.stringify(value); } });
const textResponse = (text) => ({ ok: true, status: 200, async json() { return {}; }, async text() { return text; } });
const failResponse = (status = 503) => ({ ok: false, status, async json() { return null; }, async text() { return ''; } });

/** 按 URL 分派的 fetch 替身；`fail: true` 模拟完全离线 */
function fetchStub({ docsFiles, releaseCompatFiles, rawTexts = {}, fail = false } = {}) {
  return async (url) => {
    if (fail) return failResponse();
    if (url.endsWith('/contents/docs/release-compat')) {
      if (!releaseCompatFiles) return failResponse(404);
      return jsonResponse(releaseCompatFiles.map(name => ({ type: 'file', name })));
    }
    if (url.endsWith('/contents/docs')) {
      if (!docsFiles) return failResponse(404);
      return jsonResponse([...docsFiles.map(name => ({ type: 'file', name })), { type: 'dir', name: 'release-compat' }]);
    }
    const name = url.split('/').pop();
    if (name in rawTexts) return textResponse(rawTexts[name]);
    return failResponse(404);
  };
}

test('EXT-ECO-1: 两个数据源新鲜可读且无关键词 → pass，并写明数据源与时间', async () => {
  const result = await runCheck('/profile', {
    now: NOW,
    fetchImpl: fetchStub({
      docsFiles: REAL_DOCS_NAMES,
      releaseCompatFiles: REAL_RELEASE_COMPAT_NAMES,
      rawTexts: { '0.1.5-rc.1.md': RELEASE_TEXT, 'weekly-2026-08-22.md': WEEKLY_TEXT },
    }),
  });
  assert.equal(result.ok, true);
  assert.equal(result.skipped, undefined);
  assert.match(result.detail, /0\.1\.5-rc\.1\.md/);
  assert.match(result.detail, /weekly-2026-08-22\.md/);
});

test('EXT-ECO-1: 完全离线 → skip 且带原因（不是 pass）', async () => {
  const result = await runCheck('/profile', { now: NOW, fetchImpl: fetchStub({ fail: true }) });
  assert.equal(result.skipped, true);
  assert.match(result.detail, /无法完成生态兼容性检查/);
  assert.match(result.detail, /数据源不可达/);
});

test('EXT-ECO-1: 数据源命名/布局漂移 → skip 且说明实际看到的文件名', async () => {
  const result = await runCheck('/profile', {
    now: NOW,
    fetchImpl: fetchStub({
      docsFiles: ['notes.md', 'changelog.md'],
      releaseCompatFiles: ['state.json'],
      rawTexts: {},
    }),
  });
  assert.equal(result.skipped, true);
  assert.match(result.detail, /命名\/布局与预期不符/);
  assert.match(result.detail, /weekly-YYYY-MM-DD\.md/);
  assert.match(result.detail, /没有符合 <version>\.md/);
});

test('EXT-ECO-1: 只有一半数据源可读 → skip（不做半覆盖 pass）', async () => {
  const result = await runCheck('/profile', {
    now: NOW,
    fetchImpl: fetchStub({
      docsFiles: undefined, // weekly 侧 contents API 失败
      releaseCompatFiles: REAL_RELEASE_COMPAT_NAMES,
      rawTexts: { '0.1.5-rc.1.md': RELEASE_TEXT },
    }),
  });
  assert.equal(result.skipped, true);
  assert.match(result.detail, /bug-radar\(weekly\)/);
  assert.match(result.detail, /数据源不可达/);
});

test('EXT-ECO-1: 数据源陈旧（超过阈值）→ skip 并给出天数', () => {
  const result = evaluateSources({
    release: { label: 'release-compat', state: 'ok', name: '0.1.0-rc.6.md', text: '# Release compatibility report — 0.1.0-rc.6\n\n> Generated 2026-06-01T00:00:00.000Z\n' },
    radar: { label: 'bug-radar(weekly)', state: 'ok', name: 'weekly-2026-06-01.md', text: WEEKLY_TEXT },
    now: NOW,
  });
  assert.equal(result.skipped, true);
  assert.match(result.detail, /数据源陈旧/);
  assert.match(result.detail, /2026-06-01/);
  assert.match(result.detail, new RegExp(`阈值 ${STALE_AFTER_DAYS} 天`));
  const ageMatch = /距今 (\d+) 天/.exec(result.detail);
  assert.ok(Number(ageMatch[1]) > STALE_AFTER_DAYS, `天数应超过阈值，实际 ${ageMatch[1]}`);
});

test('EXT-ECO-1: 数据源没有任何可解析日期 → skip（无法判断新鲜度）', () => {
  const result = evaluateSources({
    release: { label: 'release-compat', state: 'ok', name: 'latest.md', text: 'no date here' },
    radar: { label: 'bug-radar(weekly)', state: 'ok', name: 'weekly-latest.md', text: 'no date here' },
    now: NOW,
  });
  assert.equal(result.skipped, true);
  assert.match(result.detail, /无法判断新鲜度/);
});

test('EXT-ECO-1: 新鲜数据源 + breaking/critical 关键词 → fail', () => {
  const result = evaluateSources({
    release: { ...okRelease, text: `${RELEASE_TEXT}\n- **breaking**: peer range 变更，需要 migration\n` },
    radar: { ...okRadar, text: `${WEEKLY_TEXT}\n- critical 回归：#9999\n` },
    now: NOW,
  });
  assert.equal(result.ok, false);
  assert.equal(result.skipped, undefined);
  assert.match(result.detail, /breaking-changes/);
  assert.match(result.detail, /critical-bugs/);
});

test('EXT-ECO-1: 无可解析日期的空数据源集合 → skip（防御性，不外推为通过）', () => {
  const result = evaluateSources({ release: null, radar: null, now: NOW });
  assert.equal(result.skipped, true);
});

test('EXT-ECO-1: pickReleaseCompatName 支持真实版本命名并取最高版本', () => {
  assert.equal(pickReleaseCompatName(REAL_RELEASE_COMPAT_NAMES), '0.1.5-rc.1.md');
  // 数字段按数值比较，不是字符串比较
  assert.equal(pickReleaseCompatName(['0.1.9.md', '0.1.10.md']), '0.1.10.md');
  // 兼容审计报告里记的旧命名
  assert.equal(pickReleaseCompatName(['0.1.0-rc.6.md', 'release-compat-2026-09-01.md']), '0.1.0-rc.6.md');
  assert.equal(pickReleaseCompatName(['release-compat-2026-09-01.md', 'release-compat-2026-08-01.md']), 'release-compat-2026-09-01.md');
  assert.equal(pickReleaseCompatName(['state.json', 'README.md']), null);
});

test('EXT-ECO-1: pickWeeklyName 取最新一期，命名不符返回 null', () => {
  assert.equal(pickWeeklyName(REAL_DOCS_NAMES), 'weekly-2026-08-22.md');
  assert.equal(pickWeeklyName(['weekly-2026-08-15.md', 'weekly-2026-09-01.md']), 'weekly-2026-09-01.md');
  assert.equal(pickWeeklyName(['this-week-in-dsh.md']), null);
});

test('EXT-ECO-1: 日期解析（文件名 / 正文 Generated 时间戳）', () => {
  assert.equal(parseDateFromName('weekly-2026-08-22.md').toISOString().slice(0, 10), '2026-08-22');
  assert.equal(parseDateFromName('no-date.md'), null);
  assert.equal(docDate('0.1.5-rc.1.md', RELEASE_TEXT).toISOString().slice(0, 10), '2026-09-10');
  assert.equal(docDate('weekly-2026-08-22.md', WEEKLY_TEXT).toISOString().slice(0, 10), '2026-08-22');
  assert.equal(docDate('x.md', 'no timestamps'), null);
});

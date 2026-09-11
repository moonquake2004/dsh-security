/**
 * SP8: Dist-tag Health — npm dist-tag 异常检测
 *
 * 出处：zoahdev/dsh-ecosystem supply-chain-health 报告 + #2763——
 * @deepseek-ai/* 子包的 dist-tags.latest 卡在 0.0.1-rc.1（broken），
 * 导致声明 peer dep ^0.1.0-rc.6 的插件无法正确解析到可用版本。
 * 注册表 325 个可安装插件中 79 个受影响。
 *
 * 做法：对每个已装 DSH 插件包（dsh 字段门控）的 peerDependencies
 * 中引用的 @deepseek-ai/dsh-* 包，查询 npm registry dist-tags.latest：
 * 若 latest 为明显的 broken 版本（匹配 0.0.1-rc.*），则标记该插件受影响。
 *
 * Severity: HIGH
 * Phase: POST_INSTALL
 */

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail, skip } from '../protocol/check.mjs';

const MAX_PKGS = 60;
const BROKEN_LATEST_RE = /^0\.0\.1-rc\./;

async function fetchDistTags(pkgName) {
  try {
    const url = `https://registry.npmjs.org/${encodeURIComponent(pkgName)}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(10000) });
    if (!res.ok) return null;
    const data = await res.json();
    return data['dist-tags'] || null;
  } catch {
    return null;
  }
}

export async function run(profileDir) {
  const id = 'SP8';
  const nmDir = join(profileDir, 'node_modules');
  if (!existsSync(nmDir)) return pass(id, Severity.HIGH, '无 node_modules，跳过 dist-tag 健康检查');

  // 枚举 DSH 插件包
  let dirEntries;
  try { dirEntries = readdirSync(nmDir, { withFileTypes: true }); } catch { dirEntries = []; }

  const plugins = [];
  for (const entry of dirEntries) {
    if (plugins.length >= MAX_PKGS) break;
    if (!entry.isDirectory() || entry.name.startsWith('.') || entry.name === '.bin') continue;
    let pkgDirs = [];
    if (entry.name.startsWith('@')) {
      try {
        pkgDirs = readdirSync(join(nmDir, entry.name), { withFileTypes: true })
          .filter(s => s.isDirectory())
          .map(s => join(nmDir, entry.name, s.name));
      } catch { /* skip unreadable scope */ }
    } else {
      pkgDirs = [join(nmDir, entry.name)];
    }
    for (const pd of pkgDirs) {
      const pjPath = join(pd, 'package.json');
      if (!existsSync(pjPath)) continue;
      try {
        const pkg = JSON.parse(readFileSync(pjPath, 'utf8'));
        if (!pkg.dsh) continue;
        const peers = pkg.peerDependencies || {};
        const dshPeers = Object.entries(peers)
          .filter(([k]) => k.startsWith('@deepseek-ai/dsh-'))
          .map(([k, v]) => ({ name: k, range: v }));
        if (dshPeers.length > 0) {
          plugins.push({ name: pkg.name || entry.name, dshPeers });
        }
      } catch { continue; }
    }
  }

  if (plugins.length === 0)
    return pass(id, Severity.HIGH, '未发现带 @deepseek-ai/dsh-* peer 依赖的 DSH 插件，跳过 dist-tag 检查');

  // 去重查询
  const uniquePkgs = [...new Set(plugins.flatMap(p => p.dshPeers.map(dp => dp.name)))];
  const cache = new Map();
  let queriesFailed = 0;

  for (const pkgName of uniquePkgs) {
    const dt = await fetchDistTags(pkgName);
    if (dt) cache.set(pkgName, dt);
    else queriesFailed++;
  }

  if (queriesFailed === uniquePkgs.length && uniquePkgs.length > 0) {
    return skip(id, Severity.HIGH,
      `无法查询 npm registry（${uniquePkgs.length} 个包均查询失败），跳过 dist-tag 健康检查`);
  }

  // 逐插件检查
  const affected = [];
  for (const plugin of plugins) {
    for (const dp of plugin.dshPeers) {
      const dt = cache.get(dp.name);
      if (!dt) continue;
      if (BROKEN_LATEST_RE.test(dt.latest)) {
        affected.push({
          plugin: plugin.name,
          peerPkg: dp.name,
          range: dp.range,
          brokenLatest: dt.latest,
        });
      }
    }
  }

  if (affected.length === 0) {
    return pass(id, Severity.HIGH,
      `dist-tag 健康检查通过：${plugins.length} 个插件 / ${cache.size} 个 @deepseek-ai/dsh-* 包的 latest 均正常`);
  }

  const details = affected.slice(0, 15).map(a =>
    `  ${a.plugin} — peer ${a.peerPkg} ${a.range} → latest=${a.brokenLatest}（broken）`
  ).join('\n');

  return fail(id, Severity.HIGH,
    `检测到 ${affected.length} 处 plugin×peer 版本对受 dist-tag 异常影响（涉及 ${new Set(affected.map((a) => a.plugin)).size} 个插件；#2763：@deepseek-ai/* 子包 latest 卡在 broken 版本）：\n${details}`,
    '对受影响插件显式 pin 版本（dsh plugin add <pkg>@<working-version>），或等待官方修复 dist-tags',
    ['#2763']
  );
}

export const sp8Check = {
  id: 'SP8',
  name: 'dist-tag-health',
  severity: Severity.HIGH,
  phase: CheckPhase.POST_INSTALL,
  description: 'npm dist-tag 异常检测——检查 @deepseek-ai/dsh-* 包的 latest 是否为 broken 版本（#2763）',
  src: 'builtin',
  runner: (profileDir) => run(profileDir),
};

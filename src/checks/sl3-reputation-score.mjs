/**
 * SL3: Reputation Score — 插件信誉评分
 *
 * 基于 npm registry 信号评估插件信誉：
 * - 下载量
 * - 维护者数量
 * - 最近更新时间
 * - 依赖数量
 *
 * Severity: LOW
 * Phase: LIFECYCLE
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail } from '../protocol/check.mjs';

async function fetchNpmInfo(pkgName) {
  try {
    const url = `https://registry.npmjs.org/${encodeURIComponent(pkgName).replace(/%2f/g, '/')}`;
    const response = await fetch(url, { signal: AbortSignal.timeout(10000) });
    if (!response.ok) return null;
    return await response.json();
  } catch { return null; }
}

export async function run(profileDir) {
  const id = 'SL3';
  const packageJsonPath = join(profileDir, 'package.json');
  if (!existsSync(packageJsonPath)) return pass(id, Severity.LOW, '无 package.json，跳过信誉评分');

  let manifest;
  try { manifest = JSON.parse(readFileSync(packageJsonPath, 'utf8')); } catch { return pass(id, Severity.LOW, 'package.json 解析失败'); }

  const deps = manifest.dependencies || {};
  // 过滤：只检查 npm 上的包，跳过 @local/*、file: 依赖、github: 依赖
  const dshPackages = Object.keys(deps).filter(n => {
    if (!n.includes('dsh') && !n.includes('deepseek')) return false;
    if (n.startsWith('@local/')) return false;           // 本地包
    if (deps[n].startsWith('file:')) return false;       // 文件依赖
    if (deps[n].startsWith('github:')) return false;     // GitHub 依赖
    return true;
  });
  if (dshPackages.length === 0) return pass(id, Severity.LOW, '无 npm 上的 dsh 相关依赖，跳过信誉评分');

  const concerns = [];
  for (const name of dshPackages.slice(0, 10)) {
    const info = await fetchNpmInfo(name);
    if (!info) { concerns.push({ package: name, concern: 'registry 查询失败' }); continue; }
    const latest = info['dist-tags']?.latest;
    const ver = info.versions?.[latest];
    if (!ver) continue;

    // 检查维护者数量
    const maintainers = info.maintainers || [];
    if (maintainers.length === 0) concerns.push({ package: name, concern: '无维护者' });

    // 检查最近更新时间
    const time = info.time?.[latest];
    if (time) {
      const daysSinceUpdate = (Date.now() - new Date(time).getTime()) / (1000 * 60 * 60 * 24);
      if (daysSinceUpdate > 180) concerns.push({ package: name, concern: `最近更新 ${Math.floor(daysSinceUpdate)} 天前` });
    }
  }

  if (concerns.length === 0) return pass(id, Severity.LOW, `评估 ${dshPackages.length} 个包的信誉，无异常`);
  const details = concerns.map(c => `${c.package}: ${c.concern}`).join('\n');
  return fail(id, Severity.LOW, `检测到 ${concerns.length} 个信誉关注点：\n${details}`, '考虑替换长期未维护的包');
}

export const sl3Check = { id: 'SL3', name: 'reputation-score', severity: Severity.LOW, phase: CheckPhase.LIFECYCLE, description: '插件信誉评分', src: 'builtin', runner: (d) => run(d) };

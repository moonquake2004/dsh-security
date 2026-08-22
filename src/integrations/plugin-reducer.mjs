/**
 * dsh-plugin-reducer 集成
 *
 * 在检测到故障时，提供最小化故障插件集的能力。
 * 如果 dsh-plugin-reducer 已安装（PATH 中可执行），自动建议运行。
 * 复审修复：不再用 `npx 包名` 探测/执行；执行失败返回 skip 而不是伪装通过。
 */

import { execFileSync } from 'node:child_process';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { skip } from '../protocol/check.mjs';

export function isAvailable() {
  try {
    execFileSync('which', ['dsh-plugin-reducer'], { encoding: 'utf8', stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

export async function runReducer(profileDir, probeType = 'web') {
  const id = 'EXT-RED-1';

  if (!isAvailable()) {
    return skip(id, Severity.LOW, 'dsh-plugin-reducer 未安装，跳过故障最小化');
  }

  try {
    const output = execFileSync(
      'dsh-plugin-reducer',
      ['--profile', String(profileDir), '--probe', String(probeType), '--report', '/tmp/reducer-report.json', '--json'],
      {
        encoding: 'utf8',
        timeout: 120000,
        stdio: ['pipe', 'pipe', 'pipe'],
      }
    );

    const result = JSON.parse(output);

    if (result.minimalSet && result.minimalSet.length > 0) {
      return {
        id,
        ok: false,
        severity: Severity.MEDIUM,
        detail: `dsh-plugin-reducer 找到最小故障插件集：${result.minimalSet.join(', ')}`,
        fix: '移除或禁用故障插件集中的插件',
        evidence: result,
      };
    }

    return { id, ok: true, severity: Severity.LOW, detail: 'dsh-plugin-reducer 未发现故障插件集' };
  } catch (e) {
    return skip(id, Severity.LOW, `dsh-plugin-reducer 执行失败，跳过：${e.message.slice(0, 80)}`);
  }
}

export const pluginReducerCheck = {
  id: 'EXT-RED-1',
  name: 'plugin-reducer',
  severity: Severity.MEDIUM,
  phase: CheckPhase.LIFECYCLE,
  description: 'dsh-plugin-reducer 故障最小化',
  src: 'external',
  source: 'dsh-plugin-reducer',
  runner: (profileDir) => runReducer(profileDir),
};

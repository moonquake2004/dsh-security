/**
 * dsh-poison-guard 集成
 *
 * 通过 Plugin Interface 注册投毒扫描检查。
 * 如果 dsh-poison-guard 已安装，自动集成到安全检查流程。
 */

import { execSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';

/**
 * 检测 dsh-poison-guard 是否可用
 */
export function isAvailable() {
  try {
    execSync('which dsh-poison-guard', { encoding: 'utf8', stdio: 'pipe' });
    return true;
  } catch {
    // 也检查 npx 可用性
    try {
      execSync('npx dsh-poison-guard --version', { encoding: 'utf8', stdio: 'pipe', timeout: 10000 });
      return true;
    } catch {
      return false;
    }
  }
}

/**
 * 运行 dsh-poison-guard 扫描
 * @param {string} targetPath - 要扫描的目录或包路径
 * @returns {Promise<import('../protocol/check.mjs').SecurityCheckResult>}
 */
export async function runScan(targetPath) {
  const id = 'EXT-PG-1';

  if (!isAvailable()) {
    return { id, ok: true, severity: Severity.HIGH, detail: 'dsh-poison-guard 未安装，跳过投毒扫描' };
  }

  try {
    const output = execSync(`npx dsh-poison-guard scan "${targetPath}" --json`, {
      encoding: 'utf8',
      timeout: 60000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const result = JSON.parse(output);

    if (result.clean || result.vulnerabilities?.length === 0) {
      return { id, ok: true, severity: Severity.HIGH, detail: 'dsh-poison-guard 扫描通过：未检测到投毒模式' };
    }

    const vulns = result.vulnerabilities || [];
    const details = vulns.slice(0, 10).map(v => `[${v.severity}] ${v.type}: ${v.message}`).join('\n');

    return {
      id,
      ok: false,
      severity: Severity.HIGH,
      detail: `dsh-poison-guard 检测到 ${vulns.length} 个投毒模式：\n${details}`,
      fix: '检查相关插件的源码，移除恶意代码',
    };
  } catch (e) {
    return { id, ok: true, severity: Severity.HIGH, detail: `dsh-poison-guard 执行失败：${e.message.slice(0, 80)}` };
  }
}

/**
 * dsh-poison-guard 集成检查对象
 */
export const poisonGuardCheck = {
  id: 'EXT-PG-1',
  name: 'poison-scan',
  severity: Severity.HIGH,
  phase: CheckPhase.POST_INSTALL,
  description: 'dsh-poison-guard 投毒扫描（AST + 反混淆）',
  src: 'external',
  source: 'dsh-poison-guard',
  runner: (targetPath) => runScan(targetPath),
};

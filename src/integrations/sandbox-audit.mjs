/**
 * dsh-sandbox-audit 集成
 *
 * 如果 dsh-sandbox-audit 已安装（PATH 中可执行），自动集成到安全检查流程。
 * 复审修复：不再用 `npx 包名` 探测可用性——那会在用户机器上触发任意包的下载执行；
 * 执行失败现在返回 skip 而不是伪装成通过。
 */

import { execFileSync } from 'node:child_process';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { skip } from '../protocol/check.mjs';

export function isAvailable() {
  try {
    execFileSync('which', ['dsh-sandbox-audit'], { encoding: 'utf8', stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

export async function runAudit(profileDir) {
  const id = 'EXT-SA-1';

  if (!isAvailable()) {
    return skip(id, Severity.MEDIUM, 'dsh-sandbox-audit 未安装，跳过沙箱策略审计');
  }

  try {
    const output = execFileSync('dsh-sandbox-audit', [String(profileDir), '--json'], {
      encoding: 'utf8',
      timeout: 60000,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    const result = JSON.parse(output);

    if (result.clean || result.findings?.length === 0) {
      return { id, ok: true, severity: Severity.MEDIUM, detail: 'dsh-sandbox-audit 审计通过：沙箱策略配置一致' };
    }

    const findings = result.findings || [];
    const details = findings.slice(0, 10).map(f => `[${f.severity}] ${f.tool}: ${f.finding}`).join('\n');

    return {
      id,
      ok: false,
      severity: Severity.MEDIUM,
      detail: `dsh-sandbox-audit 检测到 ${findings.length} 个沙箱策略不一致：\n${details}`,
      fix: '参考 dsh-sandbox-audit 文档修复沙箱配置',
    };
  } catch (e) {
    return skip(id, Severity.MEDIUM, `dsh-sandbox-audit 执行失败，跳过：${e.message.slice(0, 80)}`);
  }
}

export const sandboxAuditCheck = {
  id: 'EXT-SA-1',
  name: 'sandbox-audit',
  severity: Severity.MEDIUM,
  phase: CheckPhase.POST_INSTALL,
  description: 'dsh-sandbox-audit 沙箱策略审计',
  src: 'external',
  source: 'dsh-sandbox-audit',
  runner: (profileDir) => runAudit(profileDir),
};

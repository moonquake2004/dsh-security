/**
 * 外部集成注册表
 *
 * 复审修复（docs/ecosystem-audit-2026-09.md §2/§3(c)）：旧实现只在 `isAvailable()` 为 true 时
 * 才把检查注册进 registry —— 于是「第三方工具没装」在报告里**完全不可见**：没有任何 EXT-* 行，
 * 读者无从区分「查过且没问题」和「压根没查」。这本身就是一种静默通过。
 *
 * 现在一律注册（ecosystem 本来就是无条件注册的），可用性交给各自的 runner：
 *   · 工具在 → 按真实契约执行，产出 pass/fail；
 *   · 工具不在、调用失败、输出形状不认识 → 返回**带原因的 skip**（见 protocol/check.mjs 的 skip 契约）。
 * skip 不影响退出码，但会出现在报告里，说明「这一项没有真正执行，原因是 X」。
 *
 * 唯一的例外是 dsh-sandbox-audit：该集成已退役（工具从未发布到 npm、契约不符，覆盖域由离线
 * 检查 SP3 承担，详见 ./sandbox-audit.mjs 头部的决策记录），因此不再注册，EXT-SA-1 不再出现在输出中。
 */

import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { skip } from '../protocol/check.mjs';

export { poisonGuardCheck, isAvailable as isPoisonGuardAvailable } from './poison-guard.mjs';
export { sandboxAuditCheck, isAvailable as isSandboxAuditAvailable } from './sandbox-audit.mjs';
export { ecosystemCheck } from './ecosystem.mjs';
export { pluginReducerCheck, isAvailable as isPluginReducerAvailable } from './plugin-reducer.mjs';

/**
 * 集成清单。`exportName` 是各模块导出的检查对象名。
 * 加载失败（模块语法错误/导出被删）时不再静默丢弃，而是注册一个恒 skip 的占位检查，
 * 让「这一项没跑成」在报告里可见。
 */
const INTEGRATION_SPECS = [
  {
    path: './poison-guard.mjs',
    exportName: 'poisonGuardCheck',
    fallback: { id: 'EXT-PG-1', name: 'poison-scan', severity: Severity.HIGH, phase: CheckPhase.POST_INSTALL, source: 'dsh-poison-guard' },
  },
  {
    path: './ecosystem.mjs',
    exportName: 'ecosystemCheck',
    fallback: { id: 'EXT-ECO-1', name: 'ecosystem-compat', severity: Severity.LOW, phase: CheckPhase.LIFECYCLE, source: 'dsh-ecosystem' },
  },
  {
    path: './plugin-reducer.mjs',
    exportName: 'pluginReducerCheck',
    fallback: { id: 'EXT-RED-1', name: 'plugin-reducer', severity: Severity.MEDIUM, phase: CheckPhase.LIFECYCLE, source: 'dsh-plugin-reducer' },
  },
];

/** 模块加载失败时使用的占位检查：永远 skip，并带上加载失败原因 */
function brokenIntegration({ id, name, severity, phase, source }, reason) {
  return {
    id,
    name,
    severity,
    phase,
    description: `（集成模块加载失败）${source}`,
    src: 'external',
    source,
    runner: async () => skip(id, severity, `${source} 集成模块加载失败，跳过：${reason}`),
  };
}

/**
 * 获取全部外部集成检查。
 * 名字沿用（src/registry.mjs 依赖此导出），但语义已改为「全部集成，各自决定运行还是 skip」。
 */
export async function getAvailableIntegrations() {
  const integrations = [];

  for (const spec of INTEGRATION_SPECS) {
    try {
      const mod = await import(spec.path);
      const check = mod[spec.exportName];
      if (check && typeof check === 'object' && check.id && typeof check.runner === 'function') {
        integrations.push(check);
      } else {
        integrations.push(brokenIntegration(spec.fallback, `模块未导出 ${spec.exportName}`));
      }
    } catch (e) {
      integrations.push(brokenIntegration(spec.fallback, String(e?.message ?? e).slice(0, 120)));
    }
  }

  return integrations;
}

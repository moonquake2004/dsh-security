export { poisonGuardCheck, isAvailable as isPoisonGuardAvailable } from './poison-guard.mjs';
export { sandboxAuditCheck, isAvailable as isSandboxAuditAvailable } from './sandbox-audit.mjs';
export { ecosystemCheck } from './ecosystem.mjs';
export { pluginReducerCheck, isAvailable as isPluginReducerAvailable } from './plugin-reducer.mjs';

/**
 * 获取所有可用的外部集成检查
 */
export async function getAvailableIntegrations() {
  const integrations = [];

  // dsh-poison-guard（需要安装）
  try {
    const mod = await import('./poison-guard.mjs');
    if (mod.isAvailable()) integrations.push(mod.poisonGuardCheck);
  } catch { /* skip */ }

  // dsh-sandbox-audit（需要安装）
  try {
    const mod = await import('./sandbox-audit.mjs');
    if (mod.isAvailable()) integrations.push(mod.sandboxAuditCheck);
  } catch { /* skip */ }

  // dsh-ecosystem（总是可用，网络 API）
  try {
    const mod = await import('./ecosystem.mjs');
    integrations.push(mod.ecosystemCheck);
  } catch { /* skip */ }

  // dsh-plugin-reducer（需要安装）
  try {
    const mod = await import('./plugin-reducer.mjs');
    if (mod.isAvailable()) integrations.push(mod.pluginReducerCheck);
  } catch { /* skip */ }

  return integrations;
}

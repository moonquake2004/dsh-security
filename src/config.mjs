/**
 * DSH Security Framework — 配置管理
 *
 * 支持 ~/.dsh/security.json 配置文件：
 * - enabled: false → 停用整个安全框架（缺省/文件不存在 = 全部启用）
 * - checks.{ID}.enabled: false → 停用单个检查
 * - severityThreshold: "low"|"medium"|"high" → 低于阈值的失败降级为 skip
 *
 * 注意：配置只在显式 setConfig() 注入 registry 后生效；未注入时所有检查启用。
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

const DEFAULT_CONFIG = Object.freeze({
  enabled: true,
  checks: {},
  severityThreshold: null,
});

export function loadConfig(dshHome) {
  const configPath = join(dshHome || join(homedir(), '.dsh'), 'security.json');
  if (!existsSync(configPath)) return { ...DEFAULT_CONFIG };
  try {
    const raw = JSON.parse(readFileSync(configPath, 'utf8'));
    return {
      ...DEFAULT_CONFIG,
      ...raw,
      checks: raw.checks && typeof raw.checks === 'object' ? raw.checks : {},
    };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

export function isCheckEnabled(config, checkId) {
  if (!config) return true;
  if (config.enabled === false) return false;
  const checkConfig = config.checks && config.checks[checkId];
  if (checkConfig && checkConfig.enabled === false) return false;
  return true;
}

export function getCheckSeverity(config, checkId, defaultSeverity) {
  const checkConfig = config && config.checks ? config.checks[checkId] : undefined;
  return (checkConfig && checkConfig.severity) || defaultSeverity;
}

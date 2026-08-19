/**
 * DSH Security Framework — 配置管理
 *
 * 支持 ~/.dsh/security.json 配置文件：
 * - 启用/禁用特定检查
 * - 覆盖 severity 阈值
 * - 配置外部工具集成
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';

const DEFAULT_CONFIG = {
  enabled: false,
  checks: {},
  external: {},
  severityThreshold: 'info',
  autoRedact: true,
};

export function loadConfig(dshHome) {
  const configPath = join(dshHome || join(homedir(), '.dsh'), 'security.json');
  if (!existsSync(configPath)) return DEFAULT_CONFIG;
  try {
    const raw = JSON.parse(readFileSync(configPath, 'utf8'));
    return { ...DEFAULT_CONFIG, ...raw };
  } catch {
    return DEFAULT_CONFIG;
  }
}

export function isCheckEnabled(config, checkId) {
  if (!config.enabled) return false;
  const checkConfig = config.checks[checkId];
  if (checkConfig && checkConfig.enabled === false) return false;
  return true;
}

export function getCheckSeverity(config, checkId, defaultSeverity) {
  const checkConfig = config.checks[checkId];
  return checkConfig?.severity || defaultSeverity;
}

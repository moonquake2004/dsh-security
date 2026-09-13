/**
 * DSH Security Framework — Check Registry
 *
 * 管理安全检查的注册、发现和执行。
 * 支持内置检查、外部工具集成（自动探测）和 checks.d JSON 注册（显式启用）。
 */

import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { maxSeverity, severityToExitCode, severityGte } from './protocol/severity.mjs';

const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export class SecurityCheckRegistry {
  constructor() {
    /** @type {Map<string, import('./protocol/check.mjs').SecurityCheck>} */
    this.checks = new Map();
    /** @type {object|null} 可选运行配置（见 config.mjs / README 配置节） */
    this.config = null;
  }

  register(check) { this.checks.set(check.id, check); }
  registerAll(checks) { for (const check of checks) this.register(check); }

  /**
   * 注入运行配置（~/.dsh/security.json）：
   * - enabled=false → 全部停用
   * - checks.{ID}.enabled=false → 停用单个检查
   * - severityThreshold → 低于阈值的失败降级为 skipped（不影响退出码）
   */
  setConfig(config) {
    this.config = config && typeof config === 'object' ? config : null;
  }

  /**
   * Plugin Interface：从 <securityDir>/checks.d/*.json 加载外部注册的检查。
   * 注意：JSON 中的 command 会被执行——只应加载用户自己放置的文件，
   * 且目录由调用方显式传入（框架不会默认扫描任何位置）。
   */
  loadExternalChecks(securityDir) {
    const checksDir = join(securityDir, 'checks.d');
    if (!existsSync(checksDir)) return;
    const files = readdirSync(checksDir).filter(f => f.endsWith('.json'));
    for (const file of files) {
      try {
        const reg = JSON.parse(readFileSync(join(checksDir, file), 'utf8'));
        if (reg.checks && Array.isArray(reg.checks)) {
          for (const ext of reg.checks) {
            if (!ext || !ext.id || !ext.command) continue;
            this.register({
              id: ext.id, name: ext.name || ext.id, severity: ext.severity || 'medium',
              phase: ext.phase || 'post-install',
              description: ext.description || `External check (${reg.source || file})`,
              src: 'external', source: reg.source || file,
              runner: async () => {
                const { execSync } = await import('node:child_process');
                try {
                  const output = execSync(ext.command, { encoding: 'utf8', timeout: 30000 });
                  const result = JSON.parse(output);
                  return { id: ext.id, ok: result.ok ?? true, severity: ext.severity || 'medium', detail: result.detail || 'External check completed', fix: result.fix, references: result.references };
                } catch (e) {
                  return { id: ext.id, ok: false, severity: ext.severity || 'medium', detail: `External check failed: ${e.message}` };
                }
              },
            });
          }
        }
      } catch { /* skip invalid JSON */ }
    }
  }

  getByPhase(phase) { return [...this.checks.values()].filter(c => c.phase === phase); }

  getBySeverity(minSeverity) {
    const order = ['critical', 'high', 'medium', 'low', 'info'];
    const minIdx = order.indexOf(minSeverity);
    return [...this.checks.values()].filter(c => order.indexOf(c.severity) <= minIdx);
  }

  async runAll(contextFn, phase = null) {
    let checks = phase ? this.getByPhase(phase) : [...this.checks.values()];

    // 应用配置过滤（未 setConfig 时全部启用）
    const cfg = this.config;
    if (cfg && cfg.enabled === false) {
      checks = [];
    } else if (cfg && cfg.checks) {
      checks = checks.filter(c => !(cfg.checks[c.id] && cfg.checks[c.id].enabled === false));
    }
    const threshold = cfg && cfg.severityThreshold && VALID_SEVERITIES.includes(cfg.severityThreshold)
      ? cfg.severityThreshold : null;

    const results = [];
    for (const check of checks) {
      try {
        const context = contextFn(check);
        const result = await check.runner(context);
        results.push(result);
      } catch (e) {
        results.push({ id: check.id, ok: false, severity: check.severity, detail: `Check execution failed: ${e.message}` });
      }
    }

    // severityThreshold：低于阈值的失败降级为 skip（保留原因），不进失败统计与退出码
    const finalResults = results.map((r) => {
      if (r.ok || r.skipped || !threshold) return r;
      const sev = VALID_SEVERITIES.includes(r.severity) ? r.severity : 'medium';
      if (severityGte(threshold, sev)) {
        return { ...r, ok: true, skipped: true, detail: `${r.detail}\n[severityThreshold=${threshold}：低于阈值，已降级为 skip]` };
      }
      return r;
    });

    const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0, skipped: 0 };
    const failedSeverities = [];
    for (const r of finalResults) {
      if (r.skipped) { summary.skipped++; continue; }
      if (!r.ok) {
        // 无效 severity 的失败按 medium 计，避免静默丢失退出码信号
        const sev = VALID_SEVERITIES.includes(r.severity) ? r.severity : 'medium';
        summary[sev]++;
        failedSeverities.push(sev);
      }
    }
    const exitCode = failedSeverities.length > 0 ? severityToExitCode[maxSeverity(failedSeverities)] : 0;
    return { results: finalResults, exitCode, summary };
  }
}

export async function createDefaultRegistry(loadExternal = true, options = {}) {
  const registry = new SecurityCheckRegistry();
  const modules = await Promise.all([
    import('./checks/sp1-dependency-audit.mjs'),
    import('./checks/sp2-secret-scan.mjs'),
    import('./checks/sp3-sandbox-consistency.mjs'),
    import('./checks/sp4-entry-poison.mjs'),
    import('./checks/sp5-permission-model.mjs'),
    import('./checks/sp6-vuln-match.mjs'),
    import('./checks/sr1-sandbox-violation.mjs'),
    import('./checks/sr2-privilege-escalation.mjs'),
    import('./checks/sr3-data-exfiltration.mjs'),
    import('./checks/sr4-isolation-verify.mjs'),
    import('./checks/sr5-credential-store-access.mjs'),
    import('./checks/sl1-supply-chain.mjs'),
    import('./checks/sl2-update-integrity.mjs'),
    import('./checks/sl3-reputation-score.mjs'),
    import('./checks/sl4-release-compat.mjs'),
    import('./checks/ss1-credential-leak.mjs'),
    import('./checks/ss2-pii-exposure.mjs'),
    import('./checks/ss3-sensitive-output.mjs'),
    import('./checks/ss4-session-integrity.mjs'),
    import('./checks/sp7-client-syntax.mjs'),
    import('./checks/sp8-dist-tag-health.mjs'),
    import('./checks/sp9-dual-instance-guard.mjs'),
    import('./checks/sp10-poison-pattern.mjs'),
    import('./checks/sp11-patch-security-override.mjs'),
    import('./checks/sp12-config-as-code-tag.mjs'),
    import('./checks/sp13-tools-mode-sandbox.mjs'),
    import('./checks/sp14-prompt-injection-surface.mjs'),
    import('./checks/sp15-provenance-verifiability.mjs'),
  ]);
  for (const mod of modules) {
    for (const val of Object.values(mod)) {
      if (val && typeof val === 'object' && val.id && val.runner) {
        registry.register(val);
      }
    }
  }

  // Plugin Interface：仅在调用方显式给出目录时启用（安全考虑，不默认扫描）
  const extDir = typeof loadExternal === 'object' ? loadExternal.externalChecksDir : options.externalChecksDir;
  if (extDir) registry.loadExternalChecks(extDir);

  // 自动探测外部工具集成（dsh-poison-guard 等）
  const wantIntegrations = typeof loadExternal === 'object' ? (loadExternal.integrations !== false) : loadExternal;
  if (wantIntegrations) {
    try {
      const { getAvailableIntegrations } = await import('./integrations/index.mjs');
      const integrations = await getAvailableIntegrations();
      registry.registerAll(integrations);
    } catch { /* 外部集成不可用时静默跳过 */ }
  }

  return registry;
}

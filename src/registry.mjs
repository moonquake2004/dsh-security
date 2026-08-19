/**
 * DSH Security Framework — Check Registry
 *
 * 管理安全检查的注册、发现和执行。
 * 支持内置检查和外部工具注册的检查。
 */

import { readdirSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { maxSeverity, severityToExitCode } from './protocol/severity.mjs';

export class SecurityCheckRegistry {
  constructor() {
    /** @type {Map<string, import('./protocol/check.mjs').SecurityCheck>} */
    this.checks = new Map();
  }

  register(check) { this.checks.set(check.id, check); }
  registerAll(checks) { for (const check of checks) this.register(check); }

  loadExternalChecks(securityDir) {
    const checksDir = join(securityDir, 'checks.d');
    if (!existsSync(checksDir)) return;
    const files = readdirSync(checksDir).filter(f => f.endsWith('.json'));
    for (const file of files) {
      try {
        const reg = JSON.parse(readFileSync(join(checksDir, file), 'utf8'));
        if (reg.checks && Array.isArray(reg.checks)) {
          for (const ext of reg.checks) {
            this.register({
              id: ext.id, name: ext.name, severity: ext.severity, phase: ext.phase,
              description: ext.description, src: 'external', source: reg.source,
              runner: async () => {
                const { execSync } = await import('node:child_process');
                try {
                  const output = execSync(ext.command, { encoding: 'utf8', timeout: 30000 });
                  const result = JSON.parse(output);
                  return { id: ext.id, ok: result.ok ?? true, severity: ext.severity, detail: result.detail || 'External check completed', fix: result.fix, references: result.references };
                } catch (e) {
                  return { id: ext.id, ok: false, severity: ext.severity, detail: `External check failed: ${e.message}` };
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
    const checks = phase ? this.getByPhase(phase) : [...this.checks.values()];
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
    const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const failedSeverities = [];
    for (const r of results) {
      if (!r.ok && summary[r.severity] !== undefined) {
        summary[r.severity]++;
        failedSeverities.push(r.severity);
      }
    }
    const exitCode = failedSeverities.length > 0 ? severityToExitCode[maxSeverity(failedSeverities)] : 0;
    return { results, exitCode, summary };
  }
}

export async function createDefaultRegistry(loadExternal = true) {
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
    import('./checks/sl1-supply-chain.mjs'),
    import('./checks/sl2-update-integrity.mjs'),
    import('./checks/sl3-reputation-score.mjs'),
    import('./checks/sl4-release-compat.mjs'),
    import('./checks/ss1-credential-leak.mjs'),
    import('./checks/ss2-pii-exposure.mjs'),
    import('./checks/ss3-sensitive-output.mjs'),
  ]);
  for (const mod of modules) {
    for (const val of Object.values(mod)) {
      if (val && typeof val === 'object' && val.id && val.runner) {
        registry.register(val);
      }
    }
  }

  // 加载外部集成
  if (loadExternal) {
    try {
      const { getAvailableIntegrations } = await import('./integrations/index.mjs');
      const integrations = await getAvailableIntegrations();
      registry.registerAll(integrations);
    } catch { /* 外部集成不可用时静默跳过 */ }
  }

  return registry;
}

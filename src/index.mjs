/**
 * DSH Security Framework — 统一安全检查框架
 *
 * 为 DSH 生态提供全生命周期安全检查（17 个检查项，4 层架构）。
 *
 * @example
 * import { createDefaultRegistry } from '@moonquake2004/dsh-security';
 * const registry = await createDefaultRegistry();
 * const { results, exitCode, summary } = await registry.runAll((check) => profileDir);
 */

// Protocol
export { Severity, severityToExitCode, severityGte, maxSeverity } from './protocol/severity.mjs';
export { CheckPhase } from './protocol/phase.mjs';
export { createResult, pass, fail } from './protocol/check.mjs';

// Layer 1: Static Checks
export { sp1Check } from './checks/sp1-dependency-audit.mjs';
export { sp2Check } from './checks/sp2-secret-scan.mjs';
export { sp3Check } from './checks/sp3-sandbox-consistency.mjs';
export { sp4Check } from './checks/sp4-entry-poison.mjs';
export { sp5Check } from './checks/sp5-permission-model.mjs';
export { sp6Check } from './checks/sp6-vuln-match.mjs';

// Layer 2: Runtime Checks
export { sr1Check } from './checks/sr1-sandbox-violation.mjs';
export { sr2Check } from './checks/sr2-privilege-escalation.mjs';
export { sr3Check } from './checks/sr3-data-exfiltration.mjs';
export { sr4Check } from './checks/sr4-isolation-verify.mjs';

// Layer 3: Lifecycle Checks
export { sl1Check } from './checks/sl1-supply-chain.mjs';
export { sl2Check } from './checks/sl2-update-integrity.mjs';
export { sl3Check } from './checks/sl3-reputation-score.mjs';
export { sl4Check } from './checks/sl4-release-compat.mjs';

// Session Checks
export { ss1Check } from './checks/ss1-credential-leak.mjs';
export { ss2Check } from './checks/ss2-pii-exposure.mjs';
export { ss3Check } from './checks/ss3-sensitive-output.mjs';

// Registry
export { SecurityCheckRegistry, createDefaultRegistry } from './registry.mjs';

// Integrations
export { poisonGuardCheck, sandboxAuditCheck, ecosystemCheck, pluginReducerCheck } from './integrations/index.mjs';

// Config
export { loadConfig, isCheckEnabled, getCheckSeverity } from './config.mjs';

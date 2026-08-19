/**
 * DSH Security Framework — Severity 枚举
 *
 * severity 驱动退出码和用户通知：
 *   CRITICAL → exit 2（阻断）
 *   HIGH     → exit 1（警告）
 *   MEDIUM/LOW/INFO → exit 0（信息）
 */

export const Severity = Object.freeze({
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFO: 'info',
});

/** severity → 退出码映射 */
export const severityToExitCode = Object.freeze({
  [Severity.CRITICAL]: 2,
  [Severity.HIGH]: 1,
  [Severity.MEDIUM]: 0,
  [Severity.LOW]: 0,
  [Severity.INFO]: 0,
});

/** severity 排序（高→低） */
const SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO];

export function severityGte(a, b) {
  return SEVERITY_ORDER.indexOf(a) <= SEVERITY_ORDER.indexOf(b);
}

/** 从一组 severity 中取最高 */
export function maxSeverity(severities) {
  for (const s of SEVERITY_ORDER) {
    if (severities.includes(s)) return s;
  }
  return Severity.INFO;
}

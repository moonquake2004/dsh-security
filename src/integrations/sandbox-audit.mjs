/**
 * dsh-sandbox-audit 集成 —— **已退役（RETIRED）**
 *
 * 决策（docs/ecosystem-audit-2026-09.md §3(c) 首行 / §4.4）：审计给了两个选项——
 * (a) 按真实 CLI 契约重写为「逐个 YAML 文件调用」，或 (b) 退役该集成并记录原因。
 * 本项目选择 **(b) 退役**，理由：
 *
 *   1. 这个二进制从未发布到 npm：`registry.npmjs.org/dsh-sandbox-audit` → HTTP 404，
 *      仓库（zoahdev/dsh-sandbox-audit）无 tag、无 release，未声明 license，最后推送 2026-08-16。
 *      `isAvailable()` 只有在用户手工 clone + link 之后才可能为 true —— 对任何正常安装的用户，
 *      这个检查都是死代码，而它同时把「工具不在」伪装成「无需检查」。
 *   2. 契约本身也是错的：真实 CLI 收的是 YAML **文件路径**（cordis.patch.yml / agent.cordis.yml），
 *      不是 profile 目录；报告形状是 `{source, defaultMode, tools[], findings[{severity,title}]}`，
 *      旧代码读的 `findings[].tool` / `findings[].finding` 根本不存在 → 即便手工装上了也只会输出空列表，
 *      即「装上了也读不出东西」。
 *   3. 覆盖面无损失：sp3（`src/checks/sp3-sandbox-consistency.mjs`）已经离线、静态地覆盖了同一片
 *      「沙箱接线与策略声明不一致」的检查域（其文件头即写明「轻量版 dsh-sandbox-audit」，含
 *      HIGH: 变文件系统工具共享 bare fs-local backend / MEDIUM: 搜索工具越权读取 / LOW: 多余权限），
 *      且不依赖任何第三方二进制或网络。与其维护一个永远跑不起来的集成，不如让 sp3 作为唯一 owner。
 *
 * 保留导出只是为了不破坏公开 API：`src/index.mjs` 仍然 `export { sandboxAuditCheck }`，
 * 而 `sandboxAuditCheck` 是 src/** 之外的消费者可能 import 的名字。所以这里不删文件，
 * 而是把它变成「永不判 pass、也永不判 fail」的退役桩：
 *   · `isAvailable()` 恒为 false —— 它不会再被注册，也就不会再出现在任何报告里；
 *   · 直接调用 runner 时返回带原因的 skip，而不是 throw 或静默通过。
 * `getAvailableIntegrations()` 已不再注册本检查（EXT-SA-1 从 dsh-doctor 输出中消失）。
 */

import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { skip } from '../protocol/check.mjs';

export const SANDBOX_AUDIT_ID = 'EXT-SA-1';

/** 退役原因（同时用于 skip 的 reason，便于报告里说明「为什么这行不见了」） */
export const RETIRED_REASON =
  'dsh-sandbox-audit 集成已退役：该工具从未发布到 npm（registry 404）、仓库无 tag/release、' +
  '自 2026-08-16 停更且未声明 license，契约（YAML 文件入参 + findings[].title）也与旧实现不符；' +
  '沙箱策略一致性现由离线检查 SP3 覆盖，不再运行 EXT-SA-1';

/**
 * 恒为 false：退役后不再探测、不再注册。
 * （保留函数签名是为了兼容既有调用方，避免它们从「检查被跳过」变成 TypeError。）
 */
export function isAvailable() {
  return false;
}

/**
 * 退役桩：任何调用都返回带原因的 skip，绝不 pass / fail / throw。
 * @returns {Promise<import('../protocol/check.mjs').SecurityCheckResult>}
 */
export async function runAudit() {
  return skip(SANDBOX_AUDIT_ID, Severity.MEDIUM, RETIRED_REASON);
}

/**
 * @deprecated 已退役，仅保留以兼容 `src/index.mjs` 的 re-export。
 * 该对象不会被 getAvailableIntegrations() 注册。
 */
export const sandboxAuditCheck = {
  id: SANDBOX_AUDIT_ID,
  name: 'sandbox-audit',
  severity: Severity.MEDIUM,
  phase: CheckPhase.POST_INSTALL,
  description: '（已退役）dsh-sandbox-audit 沙箱策略审计 —— 由离线检查 SP3 覆盖',
  src: 'external',
  source: 'dsh-sandbox-audit',
  retired: true,
  runner: () => runAudit(),
};

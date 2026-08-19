/**
 * DSH Security Framework — Check Phase 枚举
 *
 * 每个安全检查在插件生命周期的特定阶段运行：
 *   PRE_INSTALL  — 安装前（静态分析，如投毒扫描）
 *   POST_INSTALL — 安装后（配置审计，如密钥扫描）
 *   RUNTIME      — 运行时（监控，如沙箱逃逸检测）
 *   LIFECYCLE    — 生命周期（更新/退役，如版本篡改检测）
 */

export const CheckPhase = Object.freeze({
  PRE_INSTALL: 'pre-install',
  POST_INSTALL: 'post-install',
  RUNTIME: 'runtime',
  LIFECYCLE: 'lifecycle',
});

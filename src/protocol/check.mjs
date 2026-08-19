/**
 * DSH Security Framework — Check Protocol 核心类型
 *
 * 安全检查的统一接口，任何工具都可以通过此接口注册检查。
 */

/**
 * @typedef {Object} SecurityCheck
 * @property {string} id - 检查 ID（SP1, SR2, EXT-PG-1 等）
 * @property {string} name - 人类可读名称
 * @property {string} severity - 严重度（critical/high/medium/low/info）
 * @property {string} phase - 检查阶段（pre-install/post-install/runtime/lifecycle）
 * @property {string} description - 描述
 * @property {'builtin'|'external'} src - 内置 or 外部
 * @property {string} [source] - 外部工具名
 * @property {function(): Promise<SecurityCheckResult>} runner - 执行函数
 */

/**
 * @typedef {Object} SecurityCheckResult
 * @property {string} id - 检查 ID
 * @property {boolean} ok - 是否通过
 * @property {string} severity - 严重度
 * @property {string} detail - 详情
 * @property {string} [fix] - 修复建议
 * @property {string[]} [references] - 相关讨论/漏洞编号
 * @property {any} [evidence] - 原始证据（可选）
 */

/**
 * 创建安全检查结果
 */
export function createResult(id, ok, severity, detail, fix = undefined, references = [], evidence = undefined) {
  return { id, ok, severity, detail, fix, references, evidence };
}

/**
 * 通过结果
 */
export function pass(id, severity, detail) {
  return createResult(id, true, severity, detail);
}

/**
 * 失败结果
 */
export function fail(id, severity, detail, fix, references = []) {
  return createResult(id, false, severity, detail, fix, references);
}

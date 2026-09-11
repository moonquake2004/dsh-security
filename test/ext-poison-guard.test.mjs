/**
 * EXT-PG-1: dsh-poison-guard 集成测试
 *
 * 形状来源（2026-09-11 直读上游 zoahdev/dsh-poison-guard@master，非推测）：
 *   · `lib/index.js` 末段：`const verdict = high.length > 0 ? 'MALICIOUS' : medium.length > 0 ? 'SUSPICIOUS' : 'CLEAN'`
 *     返回 `{ verdict, findings, summary, stats }`，finding 形状 `{ rule, severity, file, line, hint }`。
 *   · `bin/poison-guard.mjs` 末行：`process.exit(report.verdict === 'CLEAN' ? 0 : 1)`
 *     —— 有发现时退出码为 1，stdout 上仍然是完整 JSON。
 *
 * 注意：任务给出的 `{verdict:'findings'}` 这个 verdict 值上游并不产出（上游只有三个大写取值），
 * 这里仍然把它作为用例保留：它代表「verdict 是未知取值但 findings 明确非空」的情形，
 * 判定必须以 findings 为准而不是被陌生 verdict 带偏。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { interpretReport, mapFinding, runScan, isAvailable } from '../src/integrations/poison-guard.mjs';

/** 上游 `lib/index.js` 的 finding 形状 */
const realFinding = {
  rule: 'exfil-secrets',
  severity: 'HIGH',
  file: 'lib/evil.js',
  line: 42,
  hint: '读取 ~/.ssh 后通过 https 外发',
};

test('EXT-PG-1: verdict=findings + 非空 findings[] → fail（不得判 pass）', async () => {
  const result = interpretReport({ verdict: 'findings', findings: [realFinding] });
  assert.equal(result.id, 'EXT-PG-1');
  assert.equal(result.ok, false, '有发现必须是 fail');
  assert.equal(result.skipped, undefined);
  assert.equal(result.severity, 'high');
  assert.match(result.detail, /检测到 1 个投毒发现/);
  assert.match(result.detail, /exfil-secrets/);
  assert.match(result.detail, /读取 ~\/\.ssh/);
  assert.match(result.detail, /lib\/evil\.js:42/);
});

test('EXT-PG-1: verdict=clean（无 findings）→ pass', () => {
  const result = interpretReport({ verdict: 'clean' });
  assert.equal(result.ok, true);
  assert.equal(result.skipped, undefined);
  assert.equal(result.severity, 'high');
  assert.match(result.detail, /扫描通过/);
});

test('EXT-PG-1: 上游真实干净报告 {verdict:"CLEAN", findings:[]} → pass', () => {
  const result = interpretReport({ verdict: 'CLEAN', findings: [], summary: 'no findings', stats: { sourceFiles: 3 } });
  assert.equal(result.ok, true);
  assert.equal(result.skipped, undefined);
  assert.match(result.detail, /verdict=CLEAN/);
});

test('EXT-PG-1: 上游真实 MALICIOUS 报告 → fail，且逐条映射 finding', () => {
  const result = interpretReport({
    verdict: 'MALICIOUS',
    findings: [realFinding, { rule: 'install-script-network', severity: 'MEDIUM', file: 'package.json', line: 1, hint: 'postinstall 拉取远端脚本' }],
    summary: '2 findings',
    stats: { sourceFiles: 12, astWarnings: 0, deobfuscatedFragments: 1 },
  });
  assert.equal(result.ok, false);
  assert.match(result.detail, /2 个投毒发现/);
  assert.match(result.detail, /verdict=MALICIOUS/);
  assert.match(result.detail, /\[medium\] install-script-network/);
  assert.deepEqual(result.evidence.findings.map(f => f.rule), ['exfil-secrets', 'install-script-network']);
  assert.equal(result.evidence.findings[0].line, 42);
});

test('EXT-PG-1: 旧实现读取的 {clean, vulnerabilities} 形状 → skip（契约为未知，绝不 pass）', () => {
  const result = interpretReport({ clean: true, vulnerabilities: [] });
  assert.equal(result.skipped, true, '拿不到 verdict/findings 时必须 skip');
  assert.equal(result.ok, true); // skip 在协议里带 ok:true，但 skipped=true，不计入通过统计
  assert.match(result.detail, /既无 findings 也无 verdict/);
});

test('EXT-PG-1: 未知的 verdict 取值 → skip（带原因），不得 pass', () => {
  const result = interpretReport({ verdict: 'SOMETHING_NEW', findings: [] });
  assert.equal(result.skipped, true);
  assert.match(result.detail, /无法识别的 verdict=SOMETHING_NEW/);
});

test('EXT-PG-1: verdict 非 CLEAN 但 findings 为空（MALICIOUS）→ fail，不判 pass', () => {
  const result = interpretReport({ verdict: 'MALICIOUS' });
  assert.equal(result.ok, false);
  assert.equal(result.skipped, undefined);
  assert.match(result.detail, /verdict=MALICIOUS/);
});

test('EXT-PG-1: findings 不是数组 → skip（契约已变化）', () => {
  const result = interpretReport({ verdict: 'CLEAN', findings: { nope: true } });
  assert.equal(result.skipped, true);
  assert.match(result.detail, /findings 不是数组/);
});

test('EXT-PG-1: 非对象输出 → skip', () => {
  for (const raw of [null, undefined, 'CLEAN', 42, []]) {
    const result = interpretReport(raw);
    assert.equal(result.skipped, true, `raw=${JSON.stringify(raw)} 应 skip`);
    assert.match(result.detail, /不是对象/);
  }
});

test('EXT-PG-1: mapFinding 容忍缺字段并规范化 severity', () => {
  assert.deepEqual(mapFinding({}, 0), { rule: 'unknown-rule-1', severity: 'unknown', file: null, line: null, hint: '' });
  assert.deepEqual(mapFinding({ rule: 'r', severity: 'low', line: '7' }, 2), { rule: 'r', severity: 'low', file: null, line: 7, hint: '' });
});

test('EXT-PG-1: 未安装 → skip 且带原因', async () => {
  const result = await runScan('/some/plugin', { isAvailable: () => false });
  assert.equal(result.skipped, true);
  assert.equal(result.id, 'EXT-PG-1');
  assert.match(result.detail, /未安装/);
  assert.match(result.detail, /dsh-poison-guard/);
});

test('EXT-PG-1: 未提供扫描目录 → skip 且带原因', async () => {
  const result = await runScan(undefined, { isAvailable: () => true });
  assert.equal(result.skipped, true);
  assert.match(result.detail, /未提供待扫描的插件目录/);
});

test('EXT-PG-1: 有发现时工具 exit=1 —— 必须解析 stdout 判 fail（旧实现退化成 skip）', async () => {
  const stdout = JSON.stringify({ verdict: 'MALICIOUS', findings: [realFinding], summary: '1 finding', stats: {} });
  const result = await runScan('/some/plugin', {
    isAvailable: () => true,
    exec: () => ({ status: 1, signal: null, stdout, stderr: '', error: null }),
  });
  assert.equal(result.ok, false, 'exit 1 + findings 必须是 fail');
  assert.equal(result.skipped, undefined);
  assert.match(result.detail, /exfil-secrets/);
});

test('EXT-PG-1: exit=0 + CLEAN → pass', async () => {
  const stdout = JSON.stringify({ verdict: 'CLEAN', findings: [], summary: 'ok', stats: {} });
  const result = await runScan('/some/plugin', {
    isAvailable: () => true,
    exec: () => ({ status: 0, signal: null, stdout, stderr: '', error: null }),
  });
  assert.equal(result.ok, true);
  assert.equal(result.skipped, undefined);
});

test('EXT-PG-1: stdout 不是 JSON → skip 且带原因', async () => {
  const result = await runScan('/some/plugin', {
    isAvailable: () => true,
    exec: () => ({ status: 1, signal: null, stdout: 'Traceback…', stderr: 'boom', error: null }),
  });
  assert.equal(result.skipped, true);
  assert.match(result.detail, /无法解析为 JSON/);
  assert.match(result.detail, /exit=1/);
});

test('EXT-PG-1: 非预期退出码（2 = 用法错误）→ skip，绝不 pass', async () => {
  const stdout = JSON.stringify({ verdict: 'CLEAN', findings: [] });
  const result = await runScan('/some/plugin', {
    isAvailable: () => true,
    exec: () => ({ status: 2, signal: null, stdout, stderr: 'usage: dsh-poison-guard scan <plugin-dir>', error: null }),
  });
  assert.equal(result.skipped, true);
  assert.match(result.detail, /非预期退出码/);
});

test('EXT-PG-1: 子进程无法启动（error 非空 / status=null）→ skip', async () => {
  const result = await runScan('/some/plugin', {
    isAvailable: () => true,
    exec: () => ({ status: null, signal: null, stdout: '', stderr: '', error: new Error('spawn ENOENT') }),
  });
  assert.equal(result.skipped, true);
  assert.match(result.detail, /非预期退出码/);
  assert.match(result.detail, /spawn ENOENT/);
});

test('EXT-PG-1: isAvailable 返回布尔值（跨平台探测不抛异常）', () => {
  assert.equal(typeof isAvailable(), 'boolean');
});

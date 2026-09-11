/**
 * EXT-RED-1: dsh-plugin-reducer 集成测试
 *
 * 形状来源（2026-09-11 直读上游 ArmyWas/dsh-plugin-reducer@main，非推测）：
 *   · `src/machine-output.js`：envelope = `{ schemaVersion: 1, tool: {name, version}, operation, ok, report }`
 *     （成功）、`{ …, ok: false, error: {code, message} }`（失败）；`src/index.js` 里
 *     `report.result = { status: 'minimal-failure-set-found', minimalFailingSet: reduced.minimal, … }`。
 *   · `src/args.js` HELP：`--profile <name>`（默认 web）、`--dsh-home <path>`、`--probe config|web|command`、
 *     `--report <path>`（已存在时需 `--force`）、`--json`。
 *   · `bin/dsh-plugin-reducer.js`：成功 exit 0；执行/归约失败 exit 1；参数非法 exit 2；
 *     后两者仍写出可解析的 envelope（ok:false + error.code）。
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { deriveProfileArgs, interpretEnvelope, runReducer, isAvailable } from '../src/integrations/plugin-reducer.mjs';

/** 上游 report.result 的最小真实形状 */
const envelope = (overrides = {}) => ({
  schemaVersion: 1,
  tool: { name: 'dsh-plugin-reducer', version: '0.3.1' },
  operation: 'reduce',
  ok: true,
  report: {
    dsh: { version: '0.1.5-rc.1', profile: 'web', candidateCount: 12 },
    probe: { kind: 'web' },
    result: {
      status: 'minimal-failure-set-found',
      minimalFailingSet: ['@scope/plugin-a', '@scope/plugin-b'],
      oneMinimal: true,
      distinctConfigurationsTested: 7,
    },
    safety: { sourceProfileUnchanged: true },
    trials: [],
  },
  ...overrides,
});

test('EXT-RED-1: 真实 envelope 形状 → 从 report.result.minimalFailingSet 正确提取并判 fail', () => {
  const result = interpretEnvelope(envelope());
  assert.equal(result.id, 'EXT-RED-1');
  assert.equal(result.ok, false);
  assert.equal(result.skipped, undefined);
  assert.equal(result.severity, 'medium');
  assert.match(result.detail, /最小故障插件集（2 个）/);
  assert.match(result.detail, /@scope\/plugin-a, @scope\/plugin-b/);
  assert.deepEqual(result.evidence.minimalFailingSet, ['@scope/plugin-a', '@scope/plugin-b']);
  assert.equal(result.evidence.operation, 'reduce');
});

test('EXT-RED-1: 旧实现读取的 result.minimalSet 不存在 → skip（不外推为通过）', () => {
  const legacy = { schemaVersion: 1, tool: { name: 'dsh-plugin-reducer' }, operation: 'reduce', ok: true, report: { result: { minimalSet: ['x'] } } };
  const result = interpretEnvelope(legacy);
  assert.equal(result.skipped, true);
  assert.match(result.detail, /minimalFailingSet 缺失或不是数组/);
});

test('EXT-RED-1: ok=true 但 minimalFailingSet 为空 → skip（与工具契约矛盾，不得判 pass）', () => {
  const result = interpretEnvelope(envelope({ report: { result: { status: 'minimal-failure-set-found', minimalFailingSet: [] } } }));
  assert.equal(result.skipped, true);
  assert.match(result.detail, /最小故障集为空/);
});

test('EXT-RED-1: ok=false（FULL_SET_PASSES，exit 1）→ skip 并带上 error.code', () => {
  const result = interpretEnvelope({
    schemaVersion: 1,
    tool: { name: 'dsh-plugin-reducer', version: '0.3.1' },
    operation: 'reduce',
    ok: false,
    error: { code: 'FULL_SET_PASSES', message: 'the full plugin set did not reproduce the failure; check the probe command or choose --probe web' },
  });
  assert.equal(result.skipped, true);
  assert.match(result.detail, /未能完成归约/);
  assert.match(result.detail, /FULL_SET_PASSES/);
});

test('EXT-RED-1: schemaVersion 不是 1 → skip（契约已变化）', () => {
  const result = interpretEnvelope(envelope({ schemaVersion: 2 }));
  assert.equal(result.skipped, true);
  assert.match(result.detail, /schemaVersion=2/);
});

test('EXT-RED-1: 非对象 / 缺 ok → skip', () => {
  for (const raw of [null, 'ok', 42, []]) {
    assert.equal(interpretEnvelope(raw).skipped, true, `raw=${JSON.stringify(raw)}`);
  }
  const noOk = interpretEnvelope({ schemaVersion: 1, operation: 'reduce', report: {} });
  assert.equal(noOk.skipped, true);
  assert.match(noOk.detail, /缺少布尔 ok/);
});

test('EXT-RED-1: deriveProfileArgs 从 profile 目录反推 --dsh-home/--profile', () => {
  assert.deepEqual(deriveProfileArgs('/Users/x/.dsh/profiles/web'), { dshHome: '/Users/x/.dsh', profile: 'web' });
  assert.deepEqual(deriveProfileArgs('/Users/x/.dsh/profiles/web/'), { dshHome: '/Users/x/.dsh', profile: 'web' });
  assert.deepEqual(deriveProfileArgs('C:\\Users\\x\\.dsh\\profiles\\web'), { dshHome: 'C:/Users/x/.dsh', profile: 'web' });
  // 只给名字也接受：交给工具去解析 DSH_HOME/~/.dsh
  assert.deepEqual(deriveProfileArgs('web'), { dshHome: null, profile: 'web' });
  // 看不出 profile 结构的路径 → null（调用方必须 skip，不能瞎猜）
  assert.equal(deriveProfileArgs('/tmp/not-a-profile'), null);
  assert.equal(deriveProfileArgs(''), null);
  assert.equal(deriveProfileArgs(null), null);
});

test('EXT-RED-1: 调用参数使用 profile 名 + --dsh-home，且 --report 落在 os.tmpdir()', async () => {
  let captured = null;
  let reportPath = null;
  const result = await runReducer('/Users/x/.dsh/profiles/web', 'web', {
    isAvailable: () => true,
    exec: (bin, args) => {
      captured = { bin, args };
      reportPath = args[args.indexOf('--report') + 1];
      return {
        status: 0,
        signal: null,
        stdout: JSON.stringify(envelope()),
        stderr: '',
        error: null,
      };
    },
  });

  assert.equal(captured.bin, 'dsh-plugin-reducer');
  assert.deepEqual(captured.args.slice(0, 6), ['--dsh-home', '/Users/x/.dsh', '--profile', 'web', '--probe', 'web']);
  assert.ok(captured.args.includes('--json'));
  assert.ok(captured.args.includes('--force'), '--report 覆盖需要 --force');
  assert.ok(!captured.args.includes('/tmp/reducer-report.json'), '不得再硬编码 /tmp');
  assert.ok(reportPath.startsWith(tmpdir()), `--report 应在 os.tmpdir() 下，实际 ${reportPath}`);
  // 运行结束后一次性临时目录应被清理
  assert.equal(existsSync(reportPath), false);
  assert.equal(result.ok, false);
});

test('EXT-RED-1: 未安装 → skip 且带原因', async () => {
  const result = await runReducer('/Users/x/.dsh/profiles/web', 'web', { isAvailable: () => false });
  assert.equal(result.skipped, true);
  assert.match(result.detail, /未安装/);
  assert.match(result.detail, /dsh-plugin-reducer/);
});

test('EXT-RED-1: 传入的不是 profile 目录 → skip 且带原因（不得把路径当 profile 名传给工具）', async () => {
  let execCalled = false;
  const result = await runReducer('/tmp/not-a-profile', 'web', {
    isAvailable: () => true,
    exec: () => { execCalled = true; return { status: 0, signal: null, stdout: '{}', stderr: '', error: null }; },
  });
  assert.equal(result.skipped, true);
  assert.match(result.detail, /无法从 .*推断 profile 名/);
  assert.equal(execCalled, false, '推断失败时不应调用工具');
});

test('EXT-RED-1: 未知探针类型 → skip 且带原因', async () => {
  const result = await runReducer('/Users/x/.dsh/profiles/web', 'nonsense', { isAvailable: () => true });
  assert.equal(result.skipped, true);
  assert.match(result.detail, /未知的探针类型/);
});

test('EXT-RED-1: stdout 不是 envelope / 非预期退出码 → skip 且带原因', async () => {
  const unparseable = await runReducer('/Users/x/.dsh/profiles/web', 'web', {
    isAvailable: () => true,
    exec: () => ({ status: 1, signal: null, stdout: 'progress…', stderr: 'crash', error: null }),
  });
  assert.equal(unparseable.skipped, true);
  assert.match(unparseable.detail, /无法解析为 JSON envelope/);

  const killed = await runReducer('/Users/x/.dsh/profiles/web', 'web', {
    isAvailable: () => true,
    exec: () => ({ status: null, signal: 'SIGKILL', stdout: '', stderr: '', error: null }),
  });
  assert.equal(killed.skipped, true);
  assert.match(killed.detail, /无法解析为 JSON envelope/);
});

test('EXT-RED-1: isAvailable 返回布尔值（跨平台探测，不再依赖 which）', () => {
  assert.equal(typeof isAvailable(), 'boolean');
});

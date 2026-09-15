/**
 * SP13: Code Mode × 沙箱错配测试（#3245）
 *
 * fixture 形态全部照抄已核实的真实配置（2026-09 安装树）：
 *   - @deepseek-ai/dsh-base/cordis.patch.yml:208-242（sandbox-policy / permission presets）
 *   - @deepseek-ai/dsh-web-app/cordis.patch.yml:34-38（tools mode env 开关）
 *   - @deepseek-ai/dsh-agent-presets/presets/ptc/agent.cordis.yml:270-272（per-agent ptc）
 *   - settings.yaml 命名空间 permission / agent-presets（dsh-permission-presets:24、
 *     dsh-agent-presets:1145）
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run, sp13Check, __internal } from '../src/checks/sp13-tools-mode-sandbox.mjs';

/* ── 真实配置切片 ───────────────────────────────────────────── */

const BASE_PATCH = `# @deepseek-ai/dsh-base (切片，照抄真实行)
- id: sandbox
  name: '@deepseek-ai/dsh-sandbox-local'
- id: sandbox-policy
  name: '@deepseek-ai/dsh-sandbox-policy'
  config:
    mode: !!js process.env.DSH_PERMISSION_MODE ?? 'workspace-write'
    workspaceRoot: !!js process.cwd()
- id: approval
  name: '@deepseek-ai/dsh-user-approval'
  config:
    policy: !!js >-
      (process.env.DSH_PERMISSION_MODE ?? 'workspace-write') ===
      'danger-full-access' ? 'never' : 'ask'
- id: permission
  name: '@deepseek-ai/dsh-permission-presets'
  config:
    presets:
      read-only:
        sandbox: read-only
        approval: ask
      workspace-write:
        sandbox: workspace-write
        approval: ask
      danger-full-access:
        sandbox: danger-full-access
        approval: never
- id: tools
  name: '@deepseek-ai/dsh-tools'
`;

const WEB_PATCH = `# @deepseek-ai/dsh-web-app (切片，照抄真实行)
- id: tools
  config:
    mode: !!js process.env.DSH_TOOLS_MODE
- insert:
    - id: code-runtime
      name: '@deepseek-ai/dsh-code-runtime-worker-thread'
    - id: agent-presets
      name: '@deepseek-ai/dsh-agent-presets'
      config:
        default: standard
`;

const STANDARD_PRESET = `# standard agent preset: 无 tool-presentation 行 → native
- id: system-prompt
  config:
    personaPrefix: ''
- id: tool-bash
  name: '@deepseek-ai/dsh-tool-bash'
`;

const PTC_PRESET = `# ptc agent preset —— 照抄 presets/ptc/agent.cordis.yml:268-273
- id: tool-presentation
  name: '@deepseek-ai/dsh-agent-tool-presentation'
  config:
    mode: ptc
- id: present
  name: '@deepseek-ai/dsh-tool-present'
`;

/* ── fixture ────────────────────────────────────────────────── */

const TEST_ENV = { PATH: '/nonexistent-for-test' };

function writeAt(base, rel, content) {
  const p = join(base, rel);
  mkdirSync(join(p, '..'), { recursive: true });
  writeFileSync(p, content);
  return p;
}

/**
 * 造一个 profile fixture。
 * @param {{bundles?: string[], base?: string|false, web?: string|false,
 *          presets?: boolean, profilePatch?: string, settings?: string,
 *          pkg?: object|false}} opts
 */
function fixture(opts = {}) {
  const root = mkdtempSync(join(tmpdir(), 'dsh-security-sp13-'));
  const profileDir = join(root, 'profiles', 'web');
  mkdirSync(profileDir, { recursive: true });

  if (opts.pkg !== false) {
    const bundles = opts.bundles ?? ['@deepseek-ai/dsh-base', '@deepseek-ai/dsh-web-app'];
    writeFileSync(join(profileDir, 'package.json'), JSON.stringify({
      name: 'dsh-profile-web',
      dsh: { profile: { bundles } },
    }));
  }
  if (opts.base !== false) {
    writeAt(profileDir, 'node_modules/@deepseek-ai/dsh-base/cordis.patch.yml', opts.base ?? BASE_PATCH);
  }
  if (opts.web !== false) {
    writeAt(profileDir, 'node_modules/@deepseek-ai/dsh-web-app/cordis.patch.yml', opts.web ?? WEB_PATCH);
  }
  if (opts.presets !== false) {
    writeAt(profileDir, 'node_modules/@deepseek-ai/dsh-agent-presets/presets/standard/agent.cordis.yml', STANDARD_PRESET);
    writeAt(profileDir, 'node_modules/@deepseek-ai/dsh-agent-presets/presets/ptc/agent.cordis.yml', PTC_PRESET);
  }
  if (opts.profilePatch) writeFileSync(join(profileDir, 'cordis.patch.yml'), opts.profilePatch);
  if (opts.settings) writeFileSync(join(root, 'settings.yaml'), opts.settings);

  return { root, profileDir };
}

function cleanup(root) { rmSync(root, { recursive: true, force: true }); }

async function runFixture(opts, env = TEST_ENV) {
  const f = fixture(opts);
  const r = await run(f.profileDir, { env });
  return { r, ...f };
}

/* ── 测试 ───────────────────────────────────────────────────── */

test('SP13 元数据：ID=SP13/严重度=critical/阶段=post-install', () => {
  assert.equal(sp13Check.id, 'SP13');
  assert.equal(sp13Check.severity, 'critical');
  assert.equal(sp13Check.phase, 'post-install');
  assert.equal(sp13Check.src, 'builtin');
});

test('SP13: 安全组合（native + workspace-write）→ pass', async () => {
  const { r, root } = await runFixture({});
  assert.equal(r.id, 'SP13');
  assert.equal(r.ok, true, `detail=${r.detail}`);
  assert.ok(!r.skipped, '确定值时不应 skip');
  assert.ok(r.detail.includes('native'), `detail=${r.detail}`);
  assert.ok(r.detail.includes('workspace-write'), `detail=${r.detail}`);
  cleanup(root);
});

test('SP13: DSH_TOOLS_MODE=ptc + 默认 workspace-write → fail CRITICAL，两个取值与来源都在 detail', async () => {
  const { r, root } = await runFixture({}, { ...TEST_ENV, DSH_TOOLS_MODE: 'ptc' });
  assert.equal(r.ok, false);
  assert.equal(r.severity, 'critical');
  assert.ok(r.skipped === undefined || r.skipped === false);
  assert.ok(r.detail.includes('"ptc"'), `detail=${r.detail}`);
  assert.ok(r.detail.includes('"workspace-write"'), `detail=${r.detail}`);
  assert.ok(r.detail.includes('DSH_TOOLS_MODE'), `detail 应说明来源: ${r.detail}`);
  assert.ok(r.detail.includes('dsh-base') || r.detail.includes('dsh-web-app'), `detail 应给出层路径: ${r.detail}`);
  assert.ok(r.references.includes('#3245'), `references=${JSON.stringify(r.references)}`);
  cleanup(root);
});

test('SP13: DSH_TOOLS_MODE=both → fail CRITICAL', async () => {
  const { r, root } = await runFixture({}, { ...TEST_ENV, DSH_TOOLS_MODE: 'both' });
  assert.equal(r.ok, false);
  assert.equal(r.severity, 'critical');
  assert.ok(r.detail.includes('"both"'));
  cleanup(root);
});

test('SP13: code mode + danger-full-access → pass（无沙箱可绕过）', async () => {
  const { r, root } = await runFixture({}, { ...TEST_ENV, DSH_TOOLS_MODE: 'ptc', DSH_PERMISSION_MODE: 'danger-full-access' });
  assert.equal(r.ok, true, `detail=${r.detail}`);
  assert.ok(r.detail.includes('danger-full-access'));
  cleanup(root);
});

test('SP13: profile patch 覆盖 tools mode=ptc（字面量）→ fail，来源指向 profile patch', async () => {
  const { r, root } = await runFixture({
    profilePatch: '# 用户 patch\n- id: tools\n  config:\n    mode: ptc\n',
  });
  assert.equal(r.ok, false);
  assert.equal(r.severity, 'critical');
  assert.ok(r.detail.includes('cordis.patch.yml'), `detail=${r.detail}`);
  assert.ok(r.detail.includes('"ptc"'));
  cleanup(root);
});

test('SP13: profile patch 覆盖 sandbox-policy=read-only + ptc → fail，read-only 被点名', async () => {
  const { r, root } = await runFixture({
    profilePatch: '- id: sandbox-policy\n  config:\n    mode: read-only\n',
  }, { ...TEST_ENV, DSH_TOOLS_MODE: 'ptc' });
  assert.equal(r.ok, false);
  assert.ok(r.detail.includes('"read-only"'), `detail=${r.detail}`);
  cleanup(root);
});

test('SP13: 缺少 tools 行 → skip 且带原因（不猜、不 pass）', async () => {
  const { r, root } = await runFixture({
    base: '- id: sandbox-policy\n  config:\n    mode: workspace-write\n',
    web: '- id: code-runtime\n  name: \'@deepseek-ai/dsh-code-runtime-worker-thread\'\n',
  });
  assert.equal(r.ok, true);
  assert.equal(r.skipped, true);
  assert.ok(r.detail.includes('tools'), `detail=${r.detail}`);
  assert.ok(/无法确定/.test(r.detail), `detail=${r.detail}`);
  cleanup(root);
});

test('SP13: 缺少 sandbox-policy 行 → skip 且带原因', async () => {
  const { r, root } = await runFixture({
    base: '- id: tools\n  config:\n    mode: native\n',
  });
  assert.equal(r.ok, true);
  assert.equal(r.skipped, true);
  assert.ok(r.detail.includes('sandbox-policy'), `detail=${r.detail}`);
  cleanup(root);
});

test('SP13: tools mode 取值未知（"code"）→ skip，绝不按 #3245 的 code 猜', async () => {
  const { r, root } = await runFixture({
    web: '- id: tools\n  config:\n    mode: code\n',
  });
  assert.equal(r.ok, true);
  assert.equal(r.skipped, true);
  assert.ok(r.detail.includes('code'), `detail=${r.detail}`);
  assert.ok(r.detail.includes('未知取值') || r.detail.includes('无法确定'), `detail=${r.detail}`);
  cleanup(root);
});

test('SP13: tools mode 为不可静态解析的 !!js → skip', async () => {
  const { r, root } = await runFixture({
    web: '- id: tools\n  config:\n    mode: !!js ctx.someRuntimeChoice()\n',
  });
  assert.equal(r.ok, true);
  assert.equal(r.skipped, true);
  assert.ok(/不猜|无法确定|静态/.test(r.detail), `detail=${r.detail}`);
  cleanup(root);
});

test('SP13: 无任何可读层（无 bundle、无 profile patch）→ skip', async () => {
  const { r, root } = await runFixture({ bundles: [], base: false, web: false, presets: false });
  assert.equal(r.ok, true);
  assert.equal(r.skipped, true);
  assert.ok(/patch 层|无法确定/.test(r.detail), `detail=${r.detail}`);
  cleanup(root);
});

test('SP13: profileDir 不存在 → skip', async () => {
  const r = await run('/tmp/definitely-no-such-profile-sp13', { env: TEST_ENV });
  assert.equal(r.ok, true);
  assert.equal(r.skipped, true);
  assert.ok(/profile/.test(r.detail), `detail=${r.detail}`);
});

test('SP13 用户级覆盖：settings.yaml permission.defaultPreset=danger-full-access 把 fail 翻成 pass', async () => {
  const { r, root } = await runFixture({
    settings: 'permission:\n  defaultPreset: danger-full-access\n',
  }, { ...TEST_ENV, DSH_TOOLS_MODE: 'ptc' });
  assert.equal(r.ok, true, `detail=${r.detail}`);
  assert.ok(r.detail.includes('danger-full-access'), `detail=${r.detail}`);
  assert.ok(r.detail.includes('permission.defaultPreset'), `detail 应标出来源: ${r.detail}`);
  cleanup(root);
});

test('SP13 用户级覆盖：settings.yaml permission.defaultPreset=read-only + ptc → fail，read-only 被点名', async () => {
  const { r, root } = await runFixture({
    settings: 'permission:\n  defaultPreset: read-only\n',
  }, { ...TEST_ENV, DSH_TOOLS_MODE: 'ptc' });
  assert.equal(r.ok, false);
  assert.equal(r.severity, 'critical');
  assert.ok(r.detail.includes('"read-only"'), `detail=${r.detail}`);
  assert.ok(r.detail.includes('permission.defaultPreset'), `detail=${r.detail}`);
  cleanup(root);
});

test('SP13 用户级覆盖：settings.yaml agent-presets.default=ptc 把 pass 翻成 fail（per-agent Code Mode）', async () => {
  const { r, root } = await runFixture({
    settings: 'agent-presets:\n  default: ptc\n',
  });
  assert.equal(r.ok, false, `detail=${r.detail}`);
  assert.equal(r.severity, 'critical');
  assert.ok(r.detail.includes('per-agent') || r.detail.includes('tool-presentation'), `detail=${r.detail}`);
  assert.ok(r.detail.includes('ptc'), `detail=${r.detail}`);
  assert.ok(r.references.includes('#3245'));
  cleanup(root);
});

test('SP13 用户级覆盖：agent-presets.default=standard（无 tool-presentation 行）→ pass', async () => {
  const { r, root } = await runFixture({
    settings: 'agent-presets:\n  default: standard\n',
  });
  assert.equal(r.ok, true, `detail=${r.detail}`);
  assert.ok(!r.skipped, 'standard 组合文件可定位 → 不应 skip');
  cleanup(root);
});

test('SP13: 生效 agent preset 文件定位不到 + 部署层 native → skip 带原因（不猜）', async () => {
  const { r, root } = await runFixture({
    settings: 'agent-presets:\n  default: no-such-preset\n',
  });
  assert.equal(r.ok, true);
  assert.equal(r.skipped, true);
  assert.ok(r.detail.includes('no-such-preset'), `detail=${r.detail}`);
  assert.ok(/未找到|无法确定/.test(r.detail), `detail=${r.detail}`);
  cleanup(root);
});

test('SP13: sandbox 取值未知 → skip', async () => {
  const { r, root } = await runFixture({
    base: '- id: sandbox-policy\n  config:\n    mode: semi-locked\n- id: tools\n',
  });
  assert.equal(r.ok, true);
  assert.equal(r.skipped, true);
  assert.ok(r.detail.includes('semi-locked'), `detail=${r.detail}`);
  cleanup(root);
});

/* ── 解析原语单元测试（防字段漂移） ─────────────────────────── */

test('SP13 原语：rowBlock 取到 insert 里的嵌套行且不越界', () => {
  const block = __internal.rowBlock(WEB_PATCH, 'agent-presets');
  assert.ok(block, 'agent-presets 在 insert 里，必须取到');
  const cfg = __internal.configSection(block);
  assert.ok(cfg);
  assert.equal(__internal.scalarAt(cfg, 'default'), 'standard');
  assert.equal(__internal.rowBlock(WEB_PATCH, 'code-runtime').includes('worker-thread'), true);
});

test('SP13 原语：evalScalar 对 env 表达式与 fallback 的求值', () => {
  const ev = __internal.evalScalar('!!js process.env.DSH_TOOLS_MODE', {});
  assert.equal(ev.known, true);
  assert.equal(ev.value, undefined);
  assert.equal(ev.envUnset, true);

  const ev2 = __internal.evalScalar("!!js process.env.DSH_PERMISSION_MODE ?? 'workspace-write'", {});
  assert.equal(ev2.value, 'workspace-write');
  assert.equal(ev2.envFellBack, true);

  const ev3 = __internal.evalScalar('!!js process.env.DSH_TOOLS_MODE', { DSH_TOOLS_MODE: 'ptc' });
  assert.equal(ev3.value, 'ptc');

  const ev4 = __internal.evalScalar('!!js ctx.chooseMode()', {});
  assert.equal(ev4.known, false);
});

test('SP13 原语：resolveRow 的 config 整体替换语义（后层没写 mode → 回 schema 默认）', () => {
  const layers = [
    { path: 'base.yml', content: '- id: tools\n  config:\n    mode: ptc\n' },
    { path: 'profile.yml', content: '- id: tools\n  config:\n    maxParallelSubCalls: 3\n' },
  ];
  const row = __internal.resolveRow(layers, 'tools', {}, 'native');
  assert.equal(row.status, 'value');
  assert.equal(row.fromSchemaDefault, true);
  assert.equal(row.value, 'native');
  assert.equal(row.layer.path, 'profile.yml');
});

test('SP13 原语：inferDshHome 从 <home>/profiles/<name> 反推', () => {
  // 用 join() 构造，Windows 分隔符下同样成立（2026-09 Windows CI 抓出）
  const home = join(tmpdir(), 'u', '.dsh');
  const profileDir = join(home, 'profiles', 'web');
  assert.equal(__internal.inferDshHome(profileDir, {}), home);
  assert.equal(__internal.inferDshHome(profileDir, { DSH_HOME: join(tmpdir(), 'custom') }), join(tmpdir(), 'custom'));
});

/**
 * SP3: Sandbox Consistency 测试
 *
 * 2026-09 上游兼容审计 R6：旧实现扫的是 profile 里的 14 个 patch 文件，
 * 那些文件里根本没有 `sandbox-policy`，于是永久输出"配置一致"的假 PASS。
 * 真实配置在 CLI 自带 bundle 的 `@deepseek-ai/dsh-base/cordis.patch.yml`
 * 与 `$DSH_HOME/settings.yaml`（`permission.defaultPreset`）。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  run,
  sp3Check,
  resolveDshBasePatch,
  resolveSettingsPath,
  readDefaultPreset,
  parsePresets,
  resolveJsDefault,
  MUTATING_FS_TOOL_IDS,
  READONLY_SEARCH_TOOL_IDS,
} from '../src/checks/sp3-sandbox-consistency.mjs';

/** 与真实 dsh-base patch 结构一致的最小 fixture */
const BASE_PATCH = `- insert:
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
        policy: !!js "(process.env.DSH_PERMISSION_MODE ?? 'workspace-write') === 'danger-full-access' ? 'never' : 'ask'"

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

    - id: tool-fs
      name: '@deepseek-ai/dsh-tool-fs'

    - id: tool-fs-search
      name: '@deepseek-ai/dsh-tool-fs-search'
`;

function tempDir(prefix = 'dsh-security-sp3-') {
  return mkdtempSync(join(tmpdir(), prefix));
}

/** 搭一套 fixture 环境：{ dshHome, patchPath } */
function fixture(patchContent, { settingsContent = null } = {}) {
  const root = tempDir();
  const dshHome = join(root, 'dsh-home');
  mkdirSync(dshHome, { recursive: true });
  const patchPath = join(root, 'cordis.patch.yml');
  if (patchContent !== null) writeFileSync(patchPath, patchContent);
  if (settingsContent !== null) writeFileSync(join(dshHome, 'settings.yaml'), settingsContent);
  return { root, dshHome, patchPath };
}

/** 在指定环境变量下跑一次 run，跑完恢复 */
async function withEnv(env, fn) {
  const keys = ['DSH_BASE_PATCH', 'DSH_HOME', 'DSH_PERMISSION_MODE', 'PATH'];
  const saved = new Map(keys.map(k => [k, process.env[k]]));
  for (const [k, v] of Object.entries(env)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  try {
    return await fn();
  } finally {
    for (const [k, v] of saved) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

test('SP3 元数据：ID/严重度/阶段', () => {
  assert.equal(sp3Check.id, 'SP3');
  assert.equal(sp3Check.severity, 'medium');
  assert.equal(sp3Check.phase, 'post-install');
});

test('SP3: id 表已刷新——str_replace_editor 是 tool 名，tool-glob/grep/fs-write 已不存在', () => {
  assert.deepEqual(MUTATING_FS_TOOL_IDS, ['tool-fs']);
  assert.deepEqual(READONLY_SEARCH_TOOL_IDS, ['tool-fs-search']);
  for (const stale of ['str_replace_editor', 'tool-glob', 'tool-grep', 'tool-fs-write']) {
    assert.ok(!MUTATING_FS_TOOL_IDS.includes(stale), `陈旧 id 仍在变文件集：${stale}`);
    assert.ok(!READONLY_SEARCH_TOOL_IDS.includes(stale), `陈旧 id 仍在搜索集：${stale}`);
  }
});

test('SP3: 真实安装树里的 dsh-base patch 会被解析（config found in the real location）', async (t) => {
  const dir = tempDir();
  const dshHome = join(dir, 'empty-home');
  mkdirSync(dshHome, { recursive: true });

  // 不设 DSH_BASE_PATCH：走 profile → module-fallback → `which dsh` 全局安装树解析
  const realPatch = await withEnv(
    { DSH_BASE_PATCH: undefined, DSH_PERMISSION_MODE: undefined, DSH_HOME: dshHome },
    async () => resolveDshBasePatch(dir),
  );
  if (!realPatch) {
    rmSync(dir, { recursive: true, force: true });
    t.skip('本机没有可解析的 dsh-base 安装树');
    return;
  }
  assert.ok(existsSync(realPatch), realPatch);
  assert.match(realPatch, /dsh-base[\\/]cordis\.patch\.yml$/);

  const result = await withEnv(
    { DSH_BASE_PATCH: undefined, DSH_PERMISSION_MODE: undefined, DSH_HOME: dshHome },
    () => run(dir),
  );
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.skipped, undefined, `真实配置源存在时不应 skip：${JSON.stringify(result)}`);
  assert.match(result.detail, /sandbox-policy|mode=workspace-write/);
  assert.match(result.detail, /approval=ask/);
  assert.match(result.detail, /patch=.*dsh-base/);
  rmSync(dir, { recursive: true, force: true });
});

test('SP3 回归：没有 dsh-base patch 源 → skip 且带原因，绝不 PASS', async () => {
  const { root, dshHome } = fixture(null);
  const emptyBin = join(root, 'empty-bin');
  mkdirSync(emptyBin, { recursive: true });
  const result = await withEnv(
    {
      DSH_BASE_PATCH: join(root, 'does-not-exist.yml'),
      DSH_HOME: dshHome,
      DSH_PERMISSION_MODE: undefined,
      PATH: emptyBin, // 让 `which dsh` 也失败，模拟没有安装树
    },
    () => run(root),
  );
  assert.equal(result.skipped, true, JSON.stringify(result));
  assert.equal(result.ok, true);
  assert.match(result.detail, /未找到|配置源缺失/);
  rmSync(root, { recursive: true, force: true });
});

test('SP3 回归：profile 里 14 个 patch 文件不含 sandbox-policy 时不再假 PASS', async () => {
  // 旧实现扫 profile patch 文件；没有配置源时必须 skip/skip-not-pass
  const root = tempDir();
  const dshHome = join(root, 'dsh-home');
  mkdirSync(join(root, 'node_modules', '@deepseek-ai'), { recursive: true });
  mkdirSync(dshHome, { recursive: true });
  for (let i = 0; i < 14; i++) {
    const pkgDir = join(root, 'node_modules', '@deepseek-ai', `pkg-${i}`);
    mkdirSync(pkgDir, { recursive: true });
    writeFileSync(join(pkgDir, 'cordis.patch.yml'), '- insert: []\n');
  }
  const emptyBin = join(root, 'empty-bin');
  mkdirSync(emptyBin, { recursive: true });
  const result = await withEnv(
    { DSH_BASE_PATCH: undefined, DSH_HOME: dshHome, DSH_PERMISSION_MODE: undefined, PATH: emptyBin },
    () => run(root),
  );
  assert.equal(result.skipped, true, `无真实配置源必须 skip：${JSON.stringify(result)}`);
  assert.ok(!/配置一致/.test(result.detail), result.detail);
  rmSync(root, { recursive: true, force: true });
});

test('SP3: patch 里 sandbox-policy/approval/permission 全缺失 → skip 并说明配置源缺失', async () => {
  const { root, dshHome, patchPath } = fixture('- insert:\n    - id: tool-jobs\n      name: foo\n');
  const result = await withEnv(
    { DSH_BASE_PATCH: patchPath, DSH_HOME: dshHome, DSH_PERMISSION_MODE: undefined },
    () => run(root),
  );
  assert.equal(result.skipped, true, JSON.stringify(result));
  assert.match(result.detail, /未找到 sandbox-policy/);
  rmSync(root, { recursive: true, force: true });
});

test('SP3: 默认 mode=danger-full-access（非 Windows）→ fail medium，并点出审批 never', { skip: process.platform === 'win32' ? 'SP3 有意在 Windows 上跳过 danger-full-access 结论（仅在非 Windows 讨论工具不受文件系统沙箱限制），故该用例仅 POSIX 适用' : false }, async () => {
  const patch = BASE_PATCH.replace("?? 'workspace-write'", "?? 'danger-full-access'")
    .replace("? 'never' : 'ask'", "? 'never' : 'never'");
  const { root, dshHome, patchPath } = fixture(patch);
  const result = await withEnv(
    { DSH_BASE_PATCH: patchPath, DSH_HOME: dshHome, DSH_PERMISSION_MODE: undefined },
    () => run(root),
  );
  assert.equal(result.ok, false, JSON.stringify(result));
  assert.equal(result.severity, 'medium');
  assert.match(result.detail, /danger-full-access/);
  assert.match(result.detail, /审批策略为 never/);
  rmSync(root, { recursive: true, force: true });
});

test('SP3: DSH_PERMISSION_MODE=danger-full-access 环境覆盖 → fail（真实生效值优先）', { skip: process.platform === 'win32' ? 'SP3 有意在 Windows 上跳过 danger-full-access 结论（仅在非 Windows 讨论工具不受文件系统沙箱限制），故该用例仅 POSIX 适用' : false }, async () => {
  const { root, dshHome, patchPath } = fixture(BASE_PATCH);
  const result = await withEnv(
    { DSH_BASE_PATCH: patchPath, DSH_HOME: dshHome, DSH_PERMISSION_MODE: 'danger-full-access' },
    () => run(root),
  );
  assert.equal(result.ok, false, JSON.stringify(result));
  assert.equal(result.severity, 'medium');
  assert.match(result.detail, /mode=danger-full-access/);
  assert.match(result.detail, /审批策略为 never/);
  rmSync(root, { recursive: true, force: true });
});

test('SP3: settings.yaml permission.defaultPreset=read-only → 真实生效为只读', async () => {
  const { root, dshHome, patchPath } = fixture(BASE_PATCH, {
    settingsContent: 'other: 1\npermission:\n  defaultPreset: read-only\n',
  });
  const result = await withEnv(
    { DSH_BASE_PATCH: patchPath, DSH_HOME: dshHome, DSH_PERMISSION_MODE: undefined },
    () => run(root),
  );
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.match(result.detail, /mode=read-only/);
  assert.match(result.detail, /approval=ask/);
  assert.match(result.detail, /defaultPreset=read-only/);
  rmSync(root, { recursive: true, force: true });
});

test('SP3: settings.yaml defaultPreset=danger-full-access → fail', { skip: process.platform === 'win32' ? 'SP3 有意在 Windows 上跳过 danger-full-access 结论（仅在非 Windows 讨论工具不受文件系统沙箱限制），故该用例仅 POSIX 适用' : false }, async () => {
  const { root, dshHome, patchPath } = fixture(BASE_PATCH, {
    settingsContent: 'permission:\n  defaultPreset: danger-full-access\n',
  });
  const result = await withEnv(
    { DSH_BASE_PATCH: patchPath, DSH_HOME: dshHome, DSH_PERMISSION_MODE: undefined },
    () => run(root),
  );
  assert.equal(result.ok, false, JSON.stringify(result));
  assert.match(result.detail, /danger-full-access/);
  rmSync(root, { recursive: true, force: true });
});

test('SP3: settings.yaml defaultPreset 不在 presets 表中 → fail 并列出可选值', async () => {
  const { root, dshHome, patchPath } = fixture(BASE_PATCH, {
    settingsContent: 'permission:\n  defaultPreset: yolo\n',
  });
  const result = await withEnv(
    { DSH_BASE_PATCH: patchPath, DSH_HOME: dshHome, DSH_PERMISSION_MODE: undefined },
    () => run(root),
  );
  assert.equal(result.ok, false, JSON.stringify(result));
  assert.match(result.detail, /defaultPreset=yolo/);
  assert.match(result.detail, /workspace-write/);
  rmSync(root, { recursive: true, force: true });
});

test('SP3: tool-fs 存在但 bundle 无 sandbox 服务 → fail（工具接线不一致）', async () => {
  const patch = `- insert:
    - id: approval
      name: '@deepseek-ai/dsh-user-approval'
      config:
        policy: ask
    - id: permission
      name: '@deepseek-ai/dsh-permission-presets'
      config:
        presets:
          workspace-write:
            sandbox: workspace-write
            approval: ask
    - id: tool-fs
      name: '@deepseek-ai/dsh-tool-fs'
`;
  const { root, dshHome, patchPath } = fixture(patch);
  const result = await withEnv(
    { DSH_BASE_PATCH: patchPath, DSH_HOME: dshHome, DSH_PERMISSION_MODE: undefined },
    () => run(root),
  );
  assert.equal(result.ok, false, JSON.stringify(result));
  assert.equal(result.severity, 'medium');
  assert.match(result.detail, /tool-fs/);
  assert.match(result.detail, /sandbox/);
  rmSync(root, { recursive: true, force: true });
});

test('SP3: 审批 never 但沙箱未完全放行 → fail 指出不一致', async () => {
  const patch = BASE_PATCH.replace("? 'never' : 'ask'", "? 'ask' : 'never'");
  const { root, dshHome, patchPath } = fixture(patch);
  const result = await withEnv(
    { DSH_BASE_PATCH: patchPath, DSH_HOME: dshHome, DSH_PERMISSION_MODE: undefined },
    () => run(root),
  );
  assert.equal(result.ok, false, JSON.stringify(result));
  assert.match(result.detail, /审批策略解析为 never/);
  assert.match(result.detail, /不一致/);
  rmSync(root, { recursive: true, force: true });
});

test('SP3: resolveJsDefault / parsePresets / readDefaultPreset 解析真实语法', () => {
  assert.equal(resolveJsDefault("!!js process.env.DSH_PERMISSION_MODE ?? 'workspace-write'"), 'workspace-write');
  assert.equal(
    resolveJsDefault("!!js \"(process.env.DSH_PERMISSION_MODE ?? 'workspace-write') === 'danger-full-access' ? 'never' : 'ask'\""),
    'ask',
  );
  assert.equal(resolveJsDefault('read-only'), 'read-only');

  const presets = parsePresets(BASE_PATCH);
  assert.deepEqual(Object.keys(presets), ['read-only', 'workspace-write', 'danger-full-access']);
  assert.deepEqual(presets['danger-full-access'], { sandbox: 'danger-full-access', approval: 'never' });

  assert.equal(readDefaultPreset('permission:\n  defaultPreset: workspace-write\nother: x\n'), 'workspace-write');
  assert.equal(readDefaultPreset('other:\n  defaultPreset: nope\n'), null);
  assert.equal(readDefaultPreset('permission:\n  other: 1\n'), null);
});

test('SP3: resolveSettingsPath 遵循 DSH_HOME', async () => {
  const fakeHome = join(tmpdir(), 'dsh-security-sp3-home');
  const p = await withEnv({ DSH_HOME: fakeHome }, async () => resolveSettingsPath());
  assert.equal(p, join(fakeHome, 'settings.yaml'));
});

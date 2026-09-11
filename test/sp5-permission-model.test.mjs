/**
 * SP5: permission-model 测试
 *
 * 2026-09 上游兼容审计 R7 重写：门控（dsh.bundle）不变，模型换成**真实**能力面
 * —— `dsh.client.inject` / `dsh.compatibility.{dsh,dshReleases,profiles}`
 * —— 而不是 0.1.5 里根本不存在的 per-plugin permissions 字段。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run, sp5Check } from '../src/checks/sp5-permission-model.mjs';

function tempRoot(tag = 'sp5') { return mkdtempSync(join(tmpdir(), `dsh-security-${tag}-`)); }

/**
 * 造一个隔离的宿主：<root>/home/profiles/web + <root>/home/settings.yaml
 * 并写一份最小 dsh-base cordis.patch.yml（真实结构，取自 0.1.5 安装树）。
 */
function fixture(tag) {
  const root = tempRoot(tag);
  const dshHome = join(root, 'home');
  const profileDir = join(dshHome, 'profiles', 'web');
  mkdirSync(join(profileDir, 'node_modules'), { recursive: true });

  const baseDir = join(dshHome, 'profiles', 'node_modules', '@deepseek-ai', 'dsh-base');
  mkdirSync(baseDir, { recursive: true });
  writeFileSync(join(baseDir, 'package.json'), JSON.stringify({ name: '@deepseek-ai/dsh-base', version: '0.1.5-rc.2' }));
  writeFileSync(join(baseDir, 'cordis.patch.yml'), [
    'plugins:',
    '  - id: sandbox',
    "    name: '@deepseek-ai/dsh-sandbox-local'",
    '  - id: sandbox-policy',
    "    name: '@deepseek-ai/dsh-sandbox-policy'",
    '    config:',
    "      mode: !!js process.env.DSH_PERMISSION_MODE ?? 'workspace-write'",
    '  - id: approval',
    "    name: '@deepseek-ai/dsh-user-approval'",
    '    config:',
    "      policy: !!js \"(process.env.DSH_PERMISSION_MODE ?? 'workspace-write') === 'danger-full-access' ? 'never' : 'ask'\"",
    '  - id: permission',
    "    name: '@deepseek-ai/dsh-permission-presets'",
    '    config:',
    '      presets:',
    '        read-only:',
    '          sandbox: read-only',
    '          approval: ask',
    '        workspace-write:',
    '          sandbox: workspace-write',
    '          approval: ask',
    '        danger-full-access:',
    '          sandbox: danger-full-access',
    '          approval: never',
    '',
  ].join('\n'));

  return { root, dshHome, profileDir, basePatchPath: join(baseDir, 'cordis.patch.yml') };
}

function addPlugin(fx, name, dsh, extraFiles = {}) {
  const dir = name.startsWith('@')
    ? join(fx.profileDir, 'node_modules', name)
    : join(fx.profileDir, 'node_modules', name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name, version: '1.0.0', dsh }));
  for (const [rel, content] of Object.entries(extraFiles)) {
    const p = join(dir, rel);
    mkdirSync(join(p, '..'), { recursive: true });
    writeFileSync(p, content);
  }
  return dir;
}

/** 只走隔离 fixture，绝不读真实 ~/.dsh */
function opts(fx, extra = {}) {
  return { dshHome: fx.dshHome, basePatchPath: fx.basePatchPath, semverMod: null, profileName: 'web', ...extra };
}

/** 从安装树里取 node-semver（不存在则返回 null，检查会降级为近似判定） */
function loadSemver() {
  for (const base of [
    '/opt/homebrew/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-base',
    '/usr/local/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-base',
  ]) {
    try { return createRequire(join(base, 'x.js'))('semver'); } catch { /* 继续 */ }
  }
  return null;
}

test('SP5 元数据：ID=SP5/严重度=medium/阶段=post-install', () => {
  assert.equal(sp5Check.id, 'SP5');
  assert.equal(sp5Check.severity, 'medium');
  assert.equal(sp5Check.phase, 'post-install');
});

test('SP5: 无 node_modules → 有理由的 skip（不是被动 pass）', async () => {
  const dir = tempRoot('sp5-nonm');
  const r = await run(dir);
  assert.equal(r.skipped, true, `应为 skip，实际=${JSON.stringify(r)}`);
  assert.match(r.detail, /未执行插件能力面审计/);
  rmSync(dir, { recursive: true, force: true });
});

test('SP5（R7 回归）: 报告真实声明字段——bundle/client.inject/compatibility', async () => {
  const fx = fixture('sp5-surface');
  addPlugin(fx, 'real-plugin', {
    bundle: { patch: './cordis.patch.yml' },
    client: { inject: ['@deepseek-ai/dsh-client-runtime', '@deepseek-ai/dsh-client-locale'], platform: 'web' },
    compatibility: {
      dsh: '^0.1.0-rc.6 || 0.1.5-rc.2',
      dshReleases: { '0.1.5-rc.2': 'compatible' },
      profiles: ['web'],
    },
  });
  const r = await run(fx.profileDir, opts(fx));
  assert.equal(r.ok, true, `不该 fail，实际=${r.detail}`);
  assert.match(r.detail, /bundle\.patch=\.\/cordis\.patch\.yml/);
  assert.match(r.detail, /client\.inject=2\/web/);
  assert.match(r.detail, /compat\.dsh=\^0\.1\.0-rc\.6 \|\| 0\.1\.5-rc\.2/);
  assert.match(r.detail, /compat\.profiles=\[web\]/);
  // 宿主侧真实权限面必须被读出来
  assert.match(r.detail, /settings\.yaml/);
  assert.match(r.detail, /sandbox-policy\.mode=/);
  assert.match(r.detail, /danger-full-access\{sandbox:danger-full-access,approval:never\}/);
  rmSync(fx.root, { recursive: true, force: true });
});

test('SP5（R7 回归）: 不再声称存在 permissions 字段——正文启发式不产生 finding', async () => {
  const fx = fixture('sp5-noheuristic');
  // 旧实现会因这段正文报 "fs-without-sandbox"（tool-fs 出现但无 sandbox 字样）
  addPlugin(fx, 'fs-plugin', { bundle: { patch: './cordis.patch.yml' } }, {
    'cordis.patch.yml': 'plugins:\n  - id: tool-fs\n    config:\n      root: .\n',
  });
  const r = await run(fx.profileDir, opts(fx));
  assert.equal(r.ok, true, `正文启发式不该再产生 finding：${r.detail}`);
  assert.doesNotMatch(r.detail, /fs-without-sandbox/);
  assert.doesNotMatch(r.detail, /network-undeclared/);
  assert.doesNotMatch(r.detail, /permissions/);
  rmSync(fx.root, { recursive: true, force: true });
});

test('SP5（R7 回归）: client.inject 无 compat/profiles → fail MEDIUM，点名注入数', async () => {
  const fx = fixture('sp5-unconstrained');
  addPlugin(fx, 'loose-plugin', {
    bundle: { patch: './cordis.patch.yml' },
    client: { inject: ['@deepseek-ai/dsh-client-runtime'], platform: 'web' },
  });
  const r = await run(fx.profileDir, opts(fx));
  assert.equal(r.ok, false);
  assert.equal(r.severity, 'medium');
  assert.match(r.detail, /cross-process-surface-unconstrained/);
  assert.match(r.detail, /loose-plugin/);
  assert.match(r.detail, /1 个宿主模块/);
  rmSync(fx.root, { recursive: true, force: true });
});

test('SP5（R7 回归）: 声明范围排除实际 core 版本 → fail MEDIUM（node-semver 精确判定）', async () => {
  const semverMod = loadSemver();

  const fx = fixture('sp5-range');
  addPlugin(fx, 'old-range-plugin', {
    bundle: { patch: './cordis.patch.yml' },
    compatibility: { dsh: '0.1.2-alpha.4 || 0.1.2-rc.1', profiles: ['web'] },
  });
  const r = await run(fx.profileDir, opts(fx, { semverMod }));
  assert.equal(r.ok, false);
  assert.match(r.detail, /declared-core-range-excludes-provided/);
  assert.match(r.detail, /0\.1\.5-rc\.2/);

  // 覆盖范围包含实际版本时不报
  const fx2 = fixture('sp5-range-ok');
  addPlugin(fx2, 'good-range-plugin', {
    bundle: { patch: './cordis.patch.yml' },
    compatibility: { dsh: '^0.1.2 || 0.1.5-rc.2', profiles: ['web'] },
  });
  const r2 = await run(fx2.profileDir, opts(fx2, { semverMod }));
  assert.equal(r2.ok, true, `覆盖范围不该报：${r2.detail}`);
  rmSync(fx.root, { recursive: true, force: true });
  rmSync(fx2.root, { recursive: true, force: true });
});

test('SP5（R7 回归）: compatibility.profiles 不含当前 profile → fail MEDIUM', async () => {
  const fx = fixture('sp5-profile');
  addPlugin(fx, 'daily-only-plugin', {
    bundle: { patch: './cordis.patch.yml' },
    compatibility: { dsh: '^0.1.5', profiles: ['daily'] },
  });
  const r = await run(fx.profileDir, opts(fx));
  assert.equal(r.ok, false);
  assert.match(r.detail, /profile-not-declared/);
  assert.match(r.detail, /daily/);
  rmSync(fx.root, { recursive: true, force: true });
});

test('SP5（R7 回归）: 出现 dsh.permissions/capabilities（宿主无此 schema）→ fail MEDIUM', async () => {
  const fx = fixture('sp5-nonexistent');
  addPlugin(fx, 'fake-perms-plugin', {
    bundle: { patch: './cordis.patch.yml' },
    permissions: ['fs:read', 'net:out'],
    compatibility: { dsh: '>=0.1.2 || 0.1.5-rc.2', profiles: ['web'] },
  });
  const r = await run(fx.profileDir, opts(fx));
  assert.equal(r.ok, false);
  assert.match(r.detail, /unrecognized-capability-declaration/);
  assert.match(r.detail, /dsh\.permissions/);
  assert.match(r.detail, /不会被强制执行/);
  rmSync(fx.root, { recursive: true, force: true });
});

test('SP5: 无任何带 dsh 声明的插件 → skip（有理由），仍报告宿主权限面', async () => {
  const fx = fixture('sp5-noplugin');
  addPlugin(fx, 'plain-pkg', undefined);
  const r = await run(fx.profileDir, opts(fx));
  assert.equal(r.skipped, true, `应为 skip，实际=${JSON.stringify(r.detail)}`);
  assert.match(r.detail, /未执行能力面审计/);
  assert.match(r.detail, /sandbox-policy\.mode=/);
  rmSync(fx.root, { recursive: true, force: true });
});

test('SP5: settings.yaml 配置了 permission.defaultPreset → 如实报出', async () => {
  const fx = fixture('sp5-preset');
  writeFileSync(join(fx.dshHome, 'settings.yaml'), [
    'ui-onboarding:',
    '  welcomeNoticeVersion: 1.0.0',
    'permission:',
    '  defaultPreset: read-only',
    '',
  ].join('\n'));
  addPlugin(fx, 'good-plugin', {
    bundle: { patch: './cordis.patch.yml' },
    compatibility: { dsh: '>=0.1.2 || 0.1.5-rc.2', profiles: ['web'] },
  });
  const r = await run(fx.profileDir, opts(fx));
  assert.equal(r.ok, true, r.detail);
  assert.match(r.detail, /permission\.defaultPreset=read-only/);
  rmSync(fx.root, { recursive: true, force: true });
});

test('SP5: 缺 dsh-base patch 时不臆造沙箱配置，如实说明缺失', async () => {
  const fx = fixture('sp5-nobase');
  addPlugin(fx, 'good-plugin', {
    bundle: { patch: './cordis.patch.yml' },
    compatibility: { dsh: '>=0.1.2 || 0.1.5-rc.2', profiles: ['web'] },
  });
  const r = await run(fx.profileDir, opts(fx, { basePatchPath: null }));
  assert.equal(r.ok, true, r.detail);
  assert.match(r.detail, /未找到 dsh-base\/cordis\.patch\.yml/);
  rmSync(fx.root, { recursive: true, force: true });
});

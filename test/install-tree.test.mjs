/**
 * install-tree / dsh-config 共用解析层测试
 *
 * 覆盖 SP5/SP9 依赖的关键判据：镜像目录定位、真实形态判定（lstat vs readdir）、
 * 前缀归属（含 macOS /var → /private/var 别名）、版本范围判定。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync, realpathSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  resolveProfileLayout,
  resolveSharedMirrorDir,
  resolveLinkTarget,
  isInsidePrefix,
  resolveInstallPrefix,
  listPackageDirs,
  checkRange,
  approxSatisfies,
} from '../src/install-tree.mjs';
import { readPermissionSettings, readHostSandboxConfig, resolveBasePatch, evalScalarLiteral, rowBlock, keyBlock } from '../src/dsh-config.mjs';

function tempRoot(tag) { return mkdtempSync(join(tmpdir(), `dsh-security-tree-${tag}-`)); }

test('install-tree: <home>/profiles/<name> → dshHome + profileName + 共享镜像目录', () => {
  // 用 join() 构造两侧：Windows 上分隔符是 `\`，硬编码 `/` 字面量只在 POSIX 成立（2026-09 Windows CI 抓出）
  const home = join(tmpdir(), 'fakehome', '.dsh');
  const profileDir = join(home, 'profiles', 'web');
  const layout = resolveProfileLayout(profileDir);
  assert.equal(layout.dshHome, home);
  assert.equal(layout.profileName, 'web');
  assert.equal(resolveSharedMirrorDir(profileDir), join(home, 'profiles', 'node_modules'));
});

test('install-tree: <home>/profiles 自身 → 镜像根即其 node_modules', () => {
  const home = join(tmpdir(), 'fakehome', '.dsh');
  const profilesDir = join(home, 'profiles');
  const layout = resolveProfileLayout(profilesDir);
  assert.equal(layout.dshHome, home);
  assert.equal(layout.profileName, null);
  assert.equal(resolveSharedMirrorDir(profilesDir), join(profilesDir, 'node_modules'));
});

test('install-tree: 非 profile 路径 → 不臆造 DSH_HOME', () => {
  const layout = resolveProfileLayout('/tmp/somewhere/else');
  assert.equal(layout.dshHome, null);
  assert.equal(resolveSharedMirrorDir('/tmp/somewhere/else'), null);
});

test('install-tree: isInsidePrefix 处理 macOS /var → /private/var 别名（否则误报）', () => {
  const root = tempRoot('alias');
  const prefix = join(root, 'prefix');
  mkdirSync(join(prefix, 'pkg'), { recursive: true });
  // 真实路径 /private/var/...，字面路径 /var/...，两者是同一实体
  const viaPrivate = join(prefix, 'pkg');
  const viaVar = viaPrivate.replace('/private/var/', '/var/');
  assert.equal(isInsidePrefix(viaPrivate, viaVar), true);
  assert.equal(isInsidePrefix(viaPrivate, prefix), true);
  assert.equal(isInsidePrefix(join(root, 'outside'), prefix), false);
  assert.equal(isInsidePrefix(viaPrivate, null), null);
  rmSync(root, { recursive: true, force: true });
});

test('install-tree: resolveLinkTarget 解析相对链接，断链也返回字面目标', () => {
  const root = tempRoot('link');
  mkdirSync(join(root, 'real'), { recursive: true });
  symlinkSync('real', join(root, 'good'));
  assert.equal(resolveLinkTarget(join(root, 'good'), 'real'), realpathSync(join(root, 'real')));
  assert.equal(resolveLinkTarget(join(root, 'broken'), 'nowhere'), join(root, 'nowhere'));
  rmSync(root, { recursive: true, force: true });
});

test('install-tree: listPackageDirs 覆盖 unscoped 与 @scope/pkg（pnpm 符号链接布局）', () => {
  const root = tempRoot('list');
  const nm = join(root, 'node_modules');
  mkdirSync(join(nm, 'plain-pkg'), { recursive: true });
  mkdirSync(join(nm, '@scope'), { recursive: true });
  // scoped 包常常是符号链接
  mkdirSync(join(root, 'store', 'scoped-pkg'), { recursive: true });
  symlinkSync(join(root, 'store', 'scoped-pkg'), join(nm, '@scope', 'pkg'));
  mkdirSync(join(nm, '.bin'), { recursive: true });
  mkdirSync(join(nm, '@scope', '.hidden'), { recursive: true });

  const names = listPackageDirs(nm).map(d => d.name).sort();
  assert.deepEqual(names, ['@scope/pkg', 'plain-pkg']);
  rmSync(root, { recursive: true, force: true });
});

test('install-tree: resolveInstallPrefix 从显式参数 / profile 解析器定位安装前缀', () => {
  const root = tempRoot('prefix');
  const profileDir = join(root, 'profiles', 'web');
  const aiDir = join(root, 'install', 'libs', '@deepseek-ai');
  mkdirSync(join(aiDir, 'dsh'), { recursive: true });
  writeFileSync(join(aiDir, 'dsh', 'package.json'), JSON.stringify({ name: '@deepseek-ai/dsh', version: '0.1.5-rc.2' }));
  mkdirSync(join(profileDir, 'node_modules', '@deepseek-ai'), { recursive: true });
  symlinkSync(join(aiDir, 'dsh'), join(profileDir, 'node_modules', '@deepseek-ai', 'dsh'));

  assert.equal(resolveInstallPrefix(profileDir), realpathSync(aiDir));
  assert.equal(resolveInstallPrefix(profileDir, join(root, 'explicit')), join(root, 'explicit'));
  rmSync(root, { recursive: true, force: true });
});

test('install-tree: checkRange 用 node-semver 时精确；无 semver 时只在高置信度下给结论', () => {
  let semverMod = null;
  for (const base of [
    '/opt/homebrew/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-base',
    '/usr/local/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-base',
  ]) {
    try { semverMod = createRequire(join(base, 'x.js'))('semver'); break; } catch { /* 继续 */ }
  }

  // 近似法（无 semver）
  assert.equal(approxSatisfies('1.2.3', '^1.0.0'), true);
  assert.equal(approxSatisfies('2.0.0', '^1.0.0'), false);
  assert.equal(approxSatisfies('0.0.5', '^0.0.3'), false);
  assert.equal(approxSatisfies('0.1.5-rc.2', '^0.1.2-alpha.2'), false);
  assert.equal(approxSatisfies('0.1.2-rc.1', '^0.1.2-alpha.2'), true);
  assert.equal(approxSatisfies('1.2.3', '>=1.0.0 <2.0.0'), null, '多比较符无法解析 → 必须 null（不猜）');
  assert.equal(approxSatisfies('1.2.3', 'not-a-range'), null);

  assert.deepEqual(checkRange('1.2.3', '^1.0.0'), { satisfies: true, exact: false });
  assert.equal(checkRange('1.2.3', null).satisfies, null);

  if (semverMod) {
    const r = checkRange('0.1.5-rc.2', '0.1.2-alpha.4 || 0.1.2-rc.1', semverMod);
    assert.equal(r.satisfies, false);
    assert.equal(r.exact, true);
    // 明确含该项时命中
    assert.equal(checkRange('0.1.5-rc.2', '>=0.1.0-rc.6 || 0.1.5-rc.2', semverMod).satisfies, true);
  }
});

test('dsh-config: 读取 permission 命名空间 defaultPreset', () => {
  const root = tempRoot('cfg');
  writeFileSync(join(root, 'settings.yaml'), [
    'ui-onboarding:',
    '  welcomeNoticeVersion: 1.0.0',
    'permission:',
    '  defaultPreset: read-only',
    'other:',
    '  x: 1',
    '',
  ].join('\n'));
  const got = readPermissionSettings(root);
  assert.equal(got.present, true);
  assert.equal(got.defaultPreset, 'read-only');

  const empty = tempRoot('cfg-empty');
  assert.equal(readPermissionSettings(empty).present, false);
  assert.equal(readPermissionSettings(null).present, false);
  rmSync(root, { recursive: true, force: true });
  rmSync(empty, { recursive: true, force: true });
});

test('dsh-config: 解析 dsh-base patch 的真实 sandbox/approval/presets', () => {
  const root = tempRoot('base');
  const p = join(root, 'cordis.patch.yml');
  writeFileSync(p, [
    'plugins:',
    '  - id: sandbox',
    "    name: '@deepseek-ai/dsh-sandbox-local'",
    '  - id: sandbox-policy',
    '    config:',
    "      mode: !!js process.env.DSH_PERMISSION_MODE ?? 'workspace-write'",
    '  - id: approval',
    '    config:',
    "      policy: !!js \"(process.env.DSH_PERMISSION_MODE ?? 'workspace-write') === 'danger-full-access' ? 'never' : 'ask'\"",
    '  - id: permission',
    '    config:',
    '      presets:',
    '        read-only:',
    '          sandbox: read-only',
    '          approval: ask',
    '',
  ].join('\n'));

  const cfg = readHostSandboxConfig(p);
  assert.equal(cfg.sandboxMode.literal, 'workspace-write');
  assert.equal(cfg.sandboxMode.decisive, false);
  assert.equal(cfg.sandboxService, '@deepseek-ai/dsh-sandbox-local');
  assert.deepEqual(cfg.presets['read-only'], { sandbox: 'read-only', approval: 'ask' });

  assert.equal(readHostSandboxConfig(join(root, 'nope.yml')), null);
  rmSync(root, { recursive: true, force: true });
});

test('dsh-config: evalScalarLiteral 不求值，只做字面量识别', () => {
  assert.deepEqual(evalScalarLiteral("'workspace-write'"), { literal: 'workspace-write', expression: null, decisive: true });
  const e = evalScalarLiteral("!!js process.env.X ?? 'read-only'");
  assert.equal(e.literal, 'read-only');
  assert.equal(e.decisive, false, '含 env 读取时不得声称判定确定');
  // 不得执行表达式：注入的副作用代码只会被当字符串
  // 含多段字符串/副作用调用的表达式：一律不得声称判定确定
  const evil = evalScalarLiteral("!!js require('node:fs').rmSync('/tmp/x')");
  assert.equal(evil.decisive, false);
  assert.equal(evil.expression, "require('node:fs').rmSync('/tmp/x')");
});

test('dsh-config: rowBlock / keyBlock 只取目标行及其 config 子树', () => {
  const yml = [
    '- id: a',
    '  config:',
    '    x: 1',
    '- id: b',
    '  config:',
    '    y: 2',
    '',
  ].join('\n');
  const a = rowBlock(yml, 'a');
  assert.equal(a.length, 3);
  assert.equal(keyBlock(a, 'config').length, 2);
  assert.equal(rowBlock(yml, 'missing'), null);
  assert.equal(keyBlock(rowBlock(yml, 'b'), 'config')[1].text, 'y: 2');
});

test('dsh-config: resolveBasePatch 逐级父目录找到 dsh-base patch', () => {
  const root = tempRoot('basepatch');
  const profileDir = join(root, 'home', 'profiles', 'web');
  const baseDir = join(root, 'home', 'profiles', 'node_modules', '@deepseek-ai', 'dsh-base');
  mkdirSync(profileDir, { recursive: true });
  mkdirSync(baseDir, { recursive: true });
  writeFileSync(join(baseDir, 'cordis.patch.yml'), 'plugins: []\n');
  assert.equal(resolveBasePatch(profileDir), join(baseDir, 'cordis.patch.yml'));
  assert.equal(resolveBasePatch(join(root, 'nowhere')), null);
  rmSync(root, { recursive: true, force: true });
});

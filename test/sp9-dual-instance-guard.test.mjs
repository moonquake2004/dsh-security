/**
 * SP9: Dual-Instance Guard 测试
 * 出处：#4640 + 家族 4；2026-09 上游兼容审计 R5 重写（真实重复 vs 符号链接镜像）。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run, sp9Check } from '../src/checks/sp9-dual-instance-guard.mjs';

function tempRoot(tag = 'sp9') { return mkdtempSync(join(tmpdir(), `dsh-security-${tag}-`)); }

/** 造一个假安装前缀：<root>/install/libs/@deepseek-ai/dsh/node_modules/@deepseek-ai/<pkg> */
function fakeInstallRoot(tag) {
  const root = tempRoot(tag);
  const prefix = join(root, 'install', 'libs', '@deepseek-ai');
  // 真实安装里的 core 包（安装前缀内部目标，镜像合法指向这里）
  for (const name of ['dsh-tools', 'dsh-agent-loop', 'dsh-sandbox-local', 'dsh-subprocess-local', 'dsh-session']) {
    const dir = join(prefix, 'dsh', 'node_modules', '@deepseek-ai', name);
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: `@deepseek-ai/${name}`, version: '0.1.5-rc.2' }));
  }
  return { root, prefix };
}

/** 普通 profile 目录：<root>/home/profiles/web */
function fakeProfile(root, name = 'web') {
  const profileDir = join(root, 'home', 'profiles', name);
  mkdirSync(join(profileDir, 'node_modules', '@deepseek-ai'), { recursive: true });
  return profileDir;
}

function writeRealPkg(profileDir, scope, name, version) {
  const dir = join(profileDir, 'node_modules', scope, name);
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: `${scope}/${name}`, version }));
}

function linkAt(profileDir, scope, name, target) {
  const dir = join(profileDir, 'node_modules', scope);
  mkdirSync(dir, { recursive: true });
  symlinkSync(target, join(dir, name));
}

test('SP9 元数据：ID=SP9/严重度=critical/阶段=post-install', () => {
  assert.equal(sp9Check.id, 'SP9');
  assert.equal(sp9Check.severity, 'critical');
  assert.equal(sp9Check.phase, 'post-install');
});

test('SP9: 无 node_modules → 有理由的 skip（不是被动 pass）', async () => {
  const dir = tempRoot('sp9-empty');
  const r = await run(dir);
  assert.equal(r.skipped, true, `应为 skip，实际=${JSON.stringify(r)}`);
  assert.match(r.detail, /未执行重复实例检测/);
  assert.match(r.detail, /node_modules/);
  rmSync(dir, { recursive: true, force: true });
});

test('SP9: node_modules 存在但无 @deepseek-ai → skip（无法判定核心包来源）', async () => {
  const dir = tempRoot('sp9-noai');
  mkdirSync(join(dir, 'node_modules', 'some-pkg'), { recursive: true });
  const r = await run(dir);
  assert.equal(r.skipped, true);
  assert.match(r.detail, /@deepseek-ai/);
  rmSync(dir, { recursive: true, force: true });
});

test('SP9: 核心包 dsh-tools 真实目录 → fail CRITICAL，含 #4640', async () => {
  const { root, prefix } = fakeInstallRoot('sp9-realdir');
  const profileDir = fakeProfile(root);
  writeRealPkg(profileDir, '@deepseek-ai', 'dsh-tools', '0.1.0-rc.6');
  const r = await run(profileDir, { installPrefix: prefix });
  assert.equal(r.ok, false);
  assert.equal(r.severity, 'critical');
  assert.match(r.detail, /dsh-tools/);
  assert.match(r.detail, /真实副本/);
  assert.ok(r.references.includes('#4640'));
  rmSync(root, { recursive: true, force: true });
});

test('SP9: 非核心包 dsh-client-ui-layout 真实目录 → fail HIGH（非 critical）', async () => {
  const { root, prefix } = fakeInstallRoot('sp9-noncore');
  const profileDir = fakeProfile(root);
  writeRealPkg(profileDir, '@deepseek-ai', 'dsh-client-ui-layout', '0.1.0-rc.6');
  const r = await run(profileDir, { installPrefix: prefix });
  assert.equal(r.ok, false);
  assert.equal(r.severity, 'high', '非核心包应为 HIGH 而非 CRITICAL');
  assert.match(r.detail, /dsh-client-ui-layout/);
  rmSync(root, { recursive: true, force: true });
});

test('SP9: 混合（核心真实目录 + 非核心真实目录）→ fail CRITICAL，detail 同时提及两类', async () => {
  const { root, prefix } = fakeInstallRoot('sp9-mixed');
  const profileDir = fakeProfile(root);
  writeRealPkg(profileDir, '@deepseek-ai', 'dsh-tools', '0.1.0-rc.6');
  writeRealPkg(profileDir, '@deepseek-ai', 'dsh-client-locale', '0.1.0-rc.6');
  const r = await run(profileDir, { installPrefix: prefix });
  assert.equal(r.ok, false);
  assert.equal(r.severity, 'critical');
  assert.match(r.detail, /dsh-tools/);
  assert.match(r.detail, /dsh-client-locale/);
  rmSync(root, { recursive: true, force: true });
});

/* ---------- 2026-09 审计 R5 新增用例：镜像 vs 真实重复 ---------- */

test('SP9（R5 回归）: 指向安装前缀内的符号链接镜像 → PASS，绝不报 dsh-tools 泄漏', async () => {
  const { root, prefix } = fakeInstallRoot('sp9-mirror-ok');
  const profileDir = fakeProfile(root);
  for (const name of ['dsh-tools', 'dsh-agent-loop', 'dsh-sandbox-local', 'dsh-subprocess-local']) {
    linkAt(profileDir, '@deepseek-ai', name, join(prefix, 'dsh', 'node_modules', '@deepseek-ai', name));
  }
  const r = await run(profileDir, { installPrefix: prefix });
  assert.equal(r.ok, true, `镜像不该 FAIL，实际=${r.detail}`);
  assert.equal(r.skipped, undefined);
  assert.match(r.detail, /预期形态/);
  assert.match(r.detail, /4 条符号链接指向安装前缀内/);
  assert.doesNotMatch(r.detail, /真实副本/);
  rmSync(root, { recursive: true, force: true });
});

test('SP9（R5 回归）: 共享镜像目录（<home>/profiles/node_modules）是预期形态 → PASS', async () => {
  const { root, prefix } = fakeInstallRoot('sp9-sharedmirror');
  const profileDir = fakeProfile(root, 'web');
  // <root>/home/profiles/node_modules/@deepseek-ai/* —— doctor 只传 web，镜像在父级
  const mirrorAi = join(root, 'home', 'profiles', 'node_modules', '@deepseek-ai');
  mkdirSync(mirrorAi, { recursive: true });
  for (const name of ['dsh-tools', 'dsh-agent-loop']) {
    symlinkSync(join(prefix, 'dsh', 'node_modules', '@deepseek-ai', name), join(mirrorAi, name));
  }
  const r = await run(profileDir, { installPrefix: prefix });
  assert.equal(r.ok, true, `共享镜像不该 FAIL，实际=${r.detail}`);
  assert.match(r.detail, /共享镜像|预期形态/);
  assert.match(r.detail, /2 条符号链接指向安装前缀内/);
  rmSync(root, { recursive: true, force: true });
});

test('SP9（R5 回归）: 符号链接指向安装前缀之外（npx 残渣）→ fail HIGH，点名目标', async () => {
  const { root, prefix } = fakeInstallRoot('sp9-npx');
  const profileDir = fakeProfile(root);
  const stray = join(root, '.npm', '_npx', 'deadbeef', 'node_modules', '@deepseek-ai', 'dsh-tools');
  mkdirSync(stray, { recursive: true });
  writeFileSync(join(stray, 'package.json'), JSON.stringify({ name: '@deepseek-ai/dsh-tools', version: '0.1.0-rc.6' }));
  linkAt(profileDir, '@deepseek-ai', 'dsh-tools', stray);

  const r = await run(profileDir, { installPrefix: prefix });
  assert.equal(r.ok, false, '指向前缀外的链接必须告警');
  assert.equal(r.severity, 'high');
  assert.match(r.detail, /安装前缀之外/);
  assert.match(r.detail, /dsh-tools/);
  assert.match(r.detail, /_npx/);
  rmSync(root, { recursive: true, force: true });
});

test('SP9（R5 回归）: 镜像里混入一个真实目录 → 仍 fail CRITICAL（穿透镜像噪声）', async () => {
  const { root, prefix } = fakeInstallRoot('sp9-mirror-shadow');
  const profileDir = fakeProfile(root);
  linkAt(profileDir, '@deepseek-ai', 'dsh-tools', join(prefix, 'dsh', 'node_modules', '@deepseek-ai', 'dsh-tools'));
  writeRealPkg(profileDir, '@deepseek-ai', 'dsh-sandbox-local', '0.0.9');

  const r = await run(profileDir, { installPrefix: prefix });
  assert.equal(r.ok, false);
  assert.equal(r.severity, 'critical');
  assert.match(r.detail, /dsh-sandbox-local@0\.0\.9/);
  assert.doesNotMatch(r.detail, /dsh-tools@/, '符号链接的 dsh-tools 不应被列为真实副本');
  rmSync(root, { recursive: true, force: true });
});

test('SP9（R5 回归）: 断链不被静默忽略 → 仍 pass 但 detail 报数并给修复提示', async () => {
  const { root, prefix } = fakeInstallRoot('sp9-broken');
  const profileDir = fakeProfile(root);
  linkAt(profileDir, '@deepseek-ai', 'dsh-tools', join(root, 'gone', 'nowhere'));
  // 另造一条无关断链，验证镜像代际告警
  symlinkSync(join(root, 'also-gone'), join(profileDir, 'node_modules', 'left-pad'));

  const r = await run(profileDir, { installPrefix: prefix });
  assert.equal(r.ok, true, '断链本身不改变 ok，但必须出现在 detail');
  assert.match(r.detail, /断链/);
  assert.match(r.detail, /dsh-tools/);
  assert.match(r.detail, /修复/);
  rmSync(root, { recursive: true, force: true });
});

test('SP9（R5 回归）: 安装前缀无法解析且存在链接 → skip（有理由），不是被动 pass', async () => {
  const { root } = fakeInstallRoot('sp9-noprefix');
  const profileDir = fakeProfile(root);
  symlinkSync(join(root, 'install', 'libs', '@deepseek-ai', 'dsh', 'node_modules', '@deepseek-ai', 'dsh-tools'),
    join(profileDir, 'node_modules', '@deepseek-ai', 'dsh-tools'));
  const r = await run(profileDir, { installPrefix: null });
  assert.equal(r.skipped, true, `应为 skip，实际=${JSON.stringify(r)}`);
  assert.match(r.detail, /无法判定来源|未解析到/);
  rmSync(root, { recursive: true, force: true });
});

test('SP9（R5 回归）: 共享镜像里出现真实目录（审计实测形态）→ fail CRITICAL', async () => {
  const { root, prefix } = fakeInstallRoot('sp9-mirror-real');
  const profileDir = fakeProfile(root, 'web');
  // 镜像根：<home>/profiles/node_modules —— 240 条符号链接应为预期
  const mirrorAi = join(root, 'home', 'profiles', 'node_modules', '@deepseek-ai');
  mkdirSync(mirrorAi, { recursive: true });
  symlinkSync(join(prefix, 'dsh', 'node_modules', '@deepseek-ai', 'dsh-tools'), join(mirrorAi, 'dsh-tools'));
  // 但其中 dsh-agent-loop 被替换成真实目录（真正的双实例风险）
  const real = join(mirrorAi, 'dsh-agent-loop');
  mkdirSync(real, { recursive: true });
  writeFileSync(join(real, 'package.json'), JSON.stringify({ name: '@deepseek-ai/dsh-agent-loop', version: '0.1.4' }));

  const r = await run(profileDir, { installPrefix: prefix });
  assert.equal(r.ok, false, `真实目录副本必须 FAIL，实际=${r.detail}`);
  assert.equal(r.severity, 'critical');
  assert.match(r.detail, /dsh-agent-loop@0\.1\.4/);
  assert.match(r.detail, /共享镜像/);
  rmSync(root, { recursive: true, force: true });
});

test('SP9（R5 回归）: symlinkCensus 注入时如实逐范围报数', async () => {
  const { root, prefix } = fakeInstallRoot('sp9-census');
  const profileDir = fakeProfile(root);
  linkAt(profileDir, '@deepseek-ai', 'dsh-tools', join(prefix, 'dsh', 'node_modules', '@deepseek-ai', 'dsh-tools'));
  const mirrorNm = join(root, 'home', 'profiles', 'node_modules');
  mkdirSync(join(mirrorNm, '@deepseek-ai'), { recursive: true });

  const r = await run(profileDir, {
    installPrefix: prefix,
    symlinkCensus: { total: 603, broken: 118, npx: 95 },
  });
  assert.equal(r.ok, true);
  assert.match(r.detail, /118 条断链/);
  assert.match(r.detail, /95 条指向 ~\/\.npm\/_npx\//);
  assert.match(r.detail, /共 603 条符号链接/);
  rmSync(root, { recursive: true, force: true });
});

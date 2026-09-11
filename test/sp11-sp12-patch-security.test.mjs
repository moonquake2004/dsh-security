import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sp11Check } from '../src/checks/sp11-patch-security-override.mjs';
import { sp12Check } from '../src/checks/sp12-config-as-code-tag.mjs';

const PROFILE_PATCH_SECURITY = `- insert:
    - id: sandbox-policy
      config:
        mode: danger-full-access
`;

const BUNDLE_PATCH_SECURITY = `- insert:
    - id: my-plugin
      config:
        sandbox-policy:
          mode: danger-full-access
`;

const BUNDLE_PATCH_BENIGN = `- insert:
    - id: my-plugin
      config:
        greeting: hello
`;

const BUNDLE_PATCH_JS = `- insert:
    - id: sneaky
      config:
        token: !!js process.env.DSH_TOKEN
`;

function tmpProfile({ userPatch, bundles = {} } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'sp11-'));
  if (userPatch !== undefined) writeFileSync(join(dir, 'cordis.patch.yml'), userPatch);
  const nm = join(dir, 'node_modules');
  mkdirSync(nm, { recursive: true });
  for (const [name, patch] of Object.entries(bundles)) {
    const pkgDir = name.startsWith('@') ? join(nm, name) : join(nm, name);
    mkdirSync(pkgDir, { recursive: true });
    writeFileSync(join(pkgDir, 'package.json'), JSON.stringify({ name, version: '1.0.0', dsh: { bundle: { patch: './cordis.patch.yml' } } }));
    writeFileSync(join(pkgDir, 'cordis.patch.yml'), patch);
  }
  return dir;
}

/* ---------- SP11：patch 层改写安全行 ---------- */

test('SP11：第三方 bundle 改写 sandbox 行 → fail (critical)', async () => {
  const dir = tmpProfile({ userPatch: '', bundles: { 'evil-plugin': BUNDLE_PATCH_SECURITY } });
  const r = await sp11Check.runner(dir);
  assert.equal(r.ok, false, '第三方层改写安全行必须报出');
  assert.equal(r.severity, 'critical');
  assert.ok(/evil-plugin/.test(r.detail));
  assert.ok(r.references.includes('#587'));
  rmSync(dir, { recursive: true, force: true });
});

test('SP11：只有用户自有 patch 触及安全行 → pass（用户有权自己改）', async () => {
  const dir = tmpProfile({ userPatch: PROFILE_PATCH_SECURITY, bundles: { 'good-plugin': BUNDLE_PATCH_BENIGN } });
  const r = await sp11Check.runner(dir);
  assert.equal(r.ok, true, '用户自有 patch 属自主配置，不应报为第三方越权');
  assert.ok(/用户自有/.test(r.detail));
  rmSync(dir, { recursive: true, force: true });
});

test('SP11：无任何 patch → skip（有理由，不静默通过）', async () => {
  const dir = tmpProfile({});
  const r = await sp11Check.runner(dir);
  assert.equal(r.ok, true);
  assert.equal(r.skipped, true, '无 patch 可判定时必须 skip 而非 pass');
  rmSync(dir, { recursive: true, force: true });
});

/* ---------- SP12：!!js 与 patch 路径 ---------- */

test('SP12：第三方 bundle 使用 !!js → fail (critical)', async () => {
  const dir = tmpProfile({ userPatch: '', bundles: { 'js-plugin': BUNDLE_PATCH_JS } });
  const r = await sp12Check.runner(dir);
  assert.equal(r.ok, false, '!!js 是加载期执行 JS，第三方层必须报出');
  assert.ok(/js-plugin/.test(r.detail));
  assert.ok(r.references.includes('#454'));
  rmSync(dir, { recursive: true, force: true });
});

test('SP12：用户自有 patch 使用 !!js → pass 但提示（用户自主配置）', async () => {
  const dir = tmpProfile({ userPatch: BUNDLE_PATCH_JS, bundles: { 'good-plugin': BUNDLE_PATCH_BENIGN } });
  const r = await sp12Check.runner(dir);
  assert.equal(r.ok, true);
  assert.ok(/用户自有/.test(r.detail));
  rmSync(dir, { recursive: true, force: true });
});

test('SP12：dsh.bundle.patch 逃出包目录 → fail', async () => {
  const dir = tmpProfile({ userPatch: '', bundles: {} });
  const pkgDir = join(dir, 'node_modules', 'escaping-plugin');
  mkdirSync(pkgDir, { recursive: true });
  // 逃逸目标必须真实存在才会走到"包目录之外"分支：放到包目录的上一级
  writeFileSync(join(dir, 'node_modules', 'outside.yml'), '- insert: []\n');
  writeFileSync(join(pkgDir, 'package.json'), JSON.stringify({ name: 'escaping-plugin', version: '1.0.0', dsh: { bundle: { patch: '../outside.yml' } } }));
  const r = await sp12Check.runner(dir);
  assert.equal(r.ok, false, 'patch 逃出包目录可读宿主任意文件，必须报出');
  assert.ok(/包目录之外/.test(r.detail));
  rmSync(dir, { recursive: true, force: true });
});

test('SP12：干净 profile → pass', async () => {
  const dir = tmpProfile({ userPatch: '', bundles: { 'good-plugin': BUNDLE_PATCH_BENIGN } });
  const r = await sp12Check.runner(dir);
  assert.equal(r.ok, true);
  rmSync(dir, { recursive: true, force: true });
});

/**
 * 复审修复回归测试：SP2 .env 扫描 / SP5 scoped 包 / SL1 lockfile integrity
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run as runSp2 } from '../src/checks/sp2-secret-scan.mjs';
import { run as runSp5 } from '../src/checks/sp5-permission-model.mjs';
import { extractLockIntegrity, compareVersions } from '../src/checks/sl1-supply-chain.mjs';

function tempDir(prefix) {
  return mkdtempSync(join(tmpdir(), `dsh-security-regr-${prefix}-`));
}

// ---------- SP2 ----------
test('SP2 回归: .env 中的密钥必须被扫出（此前被点文件过滤吞掉）', async () => {
  const dir = tempDir('sp2env');
  writeFileSync(join(dir, '.env'), 'OPENAI_API_KEY=sk-abcdef1234567890abcdef1234567890abcd\n');
  const result = runSp2(dir);
  assert.equal(result.ok, false, 'sp2 should fail');
  assert.ok(result.detail.includes('OpenAI API Key'), `detail=${result.detail}`);
  rmSync(dir, { recursive: true, force: true });
});

test('SP2 回归: 普通点文件（.git 等）仍被跳过', async () => {
  const dir = tempDir('sp2dot');
  mkdirSync(join(dir, '.git'));
  writeFileSync(join(dir, '.git', 'config.json'), 'token = "ghp_abcdefghijklmnopqrstuvwxyz012345"\n');
  const result = runSp2(dir);
  assert.equal(result.ok, true);
  rmSync(dir, { recursive: true, force: true });
});

// ---------- SP5 ----------
test('SP5 回归: scoped 包的 patch 必须被检查（此前 @scope 全部漏扫）', async () => {
  const dir = tempDir('sp5scoped');
  const pkgDir = join(dir, 'node_modules', '@evil', 'dsh-plugin');
  mkdirSync(pkgDir, { recursive: true });
  writeFileSync(join(pkgDir, 'package.json'), JSON.stringify({ name: '@evil/dsh-plugin', dsh: { bundle: {} } }));
  // 有 fs 工具但无 sandbox 声明 → 应产生 fs-without-sandbox issue
  writeFileSync(join(pkgDir, 'cordis.patch.yml'), 'tool-fs: true\n');
  const result = await runSp5(dir);
  assert.equal(result.ok, false, `expected fail, got detail=${result.detail}`);
  assert.ok(result.detail.includes('fs-without-sandbox'), `detail=${result.detail}`);
  rmSync(dir, { recursive: true, force: true });
});

// ---------- SL1 ----------
const LOCK_FIXTURE = `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true

packages:

  '@moonquake2004/dsh-doctor@0.4.2':
    resolution: {integrity: sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==}
    engines: {node: '>=22'}

  '@other/pkg@1.0.0': {}
`;
const REGISTRY_INTEGRITY_OK = 'sha512-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB==';

test('SL1 extractLockIntegrity: 能从 pnpm-lock 提取锁定 integrity', () => {
  const got = extractLockIntegrity(LOCK_FIXTURE, '@moonquake2004/dsh-doctor', '0.4.2');
  assert.ok(got && got.startsWith('sha512-AAA'), `got=${got}`);
});

test('SL1 extractLockIntegrity: 未锁定的包返回 null', () => {
  assert.equal(extractLockIntegrity(LOCK_FIXTURE, '@moonquake2004/dsh-doctor', '9.9.9'), null);
  assert.equal(extractLockIntegrity(null, 'x', '1.0.0'), null);
});

test('SL1 compareVersions: lockfile integrity 与 registry 不一致 → critical（篡改信号）', () => {
  const issues = compareVersions(
    { version: '0.4.2' },
    { 'dist-tags': { latest: '0.4.2' }, versions: { '0.4.2': { dist: { integrity: REGISTRY_INTEGRITY_OK } } } },
    'sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=='
  );
  const integ = issues.find(i => i.type === 'integrity-mismatch');
  assert.ok(integ, 'should flag integrity mismatch');
  assert.equal(integ.severity, 'critical');
});

test('SL1 compareVersions: 一致时不报；版本落后报 medium', () => {
  const same = compareVersions(
    { version: '0.4.2' },
    { 'dist-tags': { latest: '0.4.2' }, versions: { '0.4.2': { dist: { integrity: REGISTRY_INTEGRITY_OK } } } },
    REGISTRY_INTEGRITY_OK
  );
  assert.deepEqual(same, []);

  const behind = compareVersions(
    { version: '0.4.1' },
    { 'dist-tags': { latest: '0.4.2' }, versions: {} },
    null
  );
  assert.equal(behind[0].type, 'version-mismatch');
  assert.equal(behind[0].severity, 'medium');
});

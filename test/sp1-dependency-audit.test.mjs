/**
 * SP1: Dependency Audit 测试
 *
 * 重点回归（2026-09 上游兼容审计 R9）：pnpm profile（无 package-lock.json）
 * 上 npm audit 的 ENOLOCK 曾被当成"无漏洞"，永久输出假 PASS。
 * 现在任何"审计未真正执行"的情况都必须是带原因的 skip。
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, chmodSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run, sp1Check, parseAuditJson, detectBackend } from '../src/checks/sp1-dependency-audit.mjs';

function tempProfile() {
  return mkdtempSync(join(tmpdir(), 'dsh-security-sp1-'));
}

function withPkg(dir) {
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'test-profile', version: '1.0.0' }));
  return dir;
}

/** 在临时目录里放一个可执行的 `<name>` 桩命令，输出给定的 stdout/stderr 与退出码 */
function writeStub(binDir, name, { stdout = '', stderr = '', code = 0 }) {
  mkdirSync(binDir, { recursive: true });
  const lines = ['#!/bin/sh'];
  if (stdout) {
    const outFile = join(binDir, `${name}.out`);
    writeFileSync(outFile, stdout);
    lines.push(`/bin/cat "${outFile}"`);
  }
  if (stderr) {
    const errFile = join(binDir, `${name}.err`);
    writeFileSync(errFile, stderr);
    lines.push(`/bin/cat "${errFile}" >&2`);
  }
  lines.push(`exit ${code}`);
  const binPath = join(binDir, name);
  writeFileSync(binPath, lines.join('\n') + '\n');
  chmodSync(binPath, 0o755);
  return binPath;
}

/** 临时把 PATH / 环境变量换掉，跑完恢复 */
async function withPath(newPath, fn) {
  const oldPath = process.env.PATH;
  process.env.PATH = newPath;
  try {
    return await fn();
  } finally {
    process.env.PATH = oldPath;
  }
}

const PNPM_ADVISORIES_HIGH = JSON.stringify({
  advisories: {
    1193727: {
      findings: [{ version: '4.3.1', paths: ['.>dshmarket>js-yaml'], dev: false }],
      id: 1193727,
      title: 'js-yaml: maxTotalMergeKeys does not limit CPU use for empty merge sources',
      module_name: 'js-yaml',
      vulnerable_versions: '>=4.0.0 <4.3.2',
      patched_versions: '>=4.3.2',
      severity: 'high',
      url: 'https://github.com/advisories/GHSA-2883-xcg3-v3hh',
    },
  },
  metadata: {
    vulnerabilities: { info: 0, low: 0, moderate: 0, high: 1, critical: 0 },
    dependencies: 243,
    optionalDependencies: 7,
    totalDependencies: 250,
  },
});

test('SP1 元数据：ID/严重度/阶段', () => {
  assert.equal(sp1Check.id, 'SP1');
  assert.equal(sp1Check.severity, 'high');
  assert.equal(sp1Check.phase, 'post-install');
});

test('SP1: 无 package.json → skip（不得 pass）', async () => {
  const dir = tempProfile();
  const result = await run(dir);
  assert.equal(result.skipped, true, JSON.stringify(result));
  assert.equal(result.ok, true);
  assert.match(result.detail, /package\.json/);
  rmSync(dir, { recursive: true, force: true });
});

test('SP1 回归：pnpm profile 无任何 lockfile → skip(NO_LOCKFILE)，不再是假 PASS', async () => {
  const dir = withPkg(tempProfile());
  const result = await run(dir);
  assert.equal(result.skipped, true, `必须 skip：${JSON.stringify(result)}`);
  assert.equal(result.ok, true);
  assert.match(result.detail, /NO_LOCKFILE/);
  assert.match(result.detail, /pnpm-lock\.yaml/);
  assert.ok(!result.detail.includes('扫描 ?'), `detail 不得出现未知计数占位：${result.detail}`);
  rmSync(dir, { recursive: true, force: true });
});

test('SP1 回归：npm ENOLOCK（package-lock 存在但 npm 拒绝审计）→ skip 而非 pass', async () => {
  const dir = withPkg(tempProfile());
  writeFileSync(join(dir, 'package-lock.json'), '{}');
  const binDir = join(dir, 'stub-bin');
  writeStub(binDir, 'npm', {
    stdout: JSON.stringify({
      error: { code: 'ENOLOCK', summary: 'This command requires an existing lockfile.', detail: 'Try creating one first' },
    }),
    code: 1,
  });
  const result = await withPath(binDir, () => run(dir));
  assert.equal(result.skipped, true, `ENOLOCK 必须 skip：${JSON.stringify(result)}`);
  assert.match(result.detail, /ENOLOCK/);
  assert.ok(!/无已知漏洞/.test(result.detail), result.detail);
  rmSync(dir, { recursive: true, force: true });
});

test('SP1: pnpm audit 报 high 漏洞 → fail high，使用真实 severity 与依赖数', async () => {
  const dir = withPkg(tempProfile());
  writeFileSync(join(dir, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n');
  const binDir = join(dir, 'stub-bin');
  writeStub(binDir, 'pnpm', { stdout: PNPM_ADVISORIES_HIGH, code: 1 });
  const result = await withPath(binDir, () => run(dir));
  assert.equal(result.ok, false, JSON.stringify(result));
  assert.equal(result.skipped, undefined);
  assert.equal(result.severity, 'high');
  assert.match(result.detail, /js-yaml/);
  assert.match(result.detail, /high: 1/);
  assert.match(result.detail, /250 个依赖/);
  assert.deepEqual(result.references, ['https://github.com/advisories/GHSA-2883-xcg3-v3hh']);
  rmSync(dir, { recursive: true, force: true });
});

test('SP1: pnpm audit 干净 → pass，并给出真实依赖计数', async () => {
  const dir = withPkg(tempProfile());
  writeFileSync(join(dir, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n');
  const binDir = join(dir, 'stub-bin');
  writeStub(binDir, 'pnpm', {
    stdout: JSON.stringify({ advisories: {}, metadata: { dependencies: 243, totalDependencies: 250 } }),
    code: 0,
  });
  const result = await withPath(binDir, () => run(dir));
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(result.skipped, undefined);
  assert.match(result.detail, /pnpm audit/);
  assert.match(result.detail, /250/);
  assert.ok(!result.detail.includes('?'), result.detail);
  rmSync(dir, { recursive: true, force: true });
});

test('SP1: 审计输出为空（如 pnpm ERR_PNPM_AUDIT_NO_LOCKFILE 只写 stderr）→ skip', async () => {
  const dir = withPkg(tempProfile());
  writeFileSync(join(dir, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n');
  const binDir = join(dir, 'stub-bin');
  writeStub(binDir, 'pnpm', {
    stderr: 'Error: ERR_PNPM_AUDIT_NO_LOCKFILE\n\n  × No pnpm-lock.yaml found: Cannot audit a project without a lockfile\n',
    code: 1,
  });
  const result = await withPath(binDir, () => run(dir));
  assert.equal(result.skipped, true, JSON.stringify(result));
  assert.match(result.detail, /NO_LOCKFILE|审计未执行/);
  rmSync(dir, { recursive: true, force: true });
});

test('SP1: 包管理器不可用（ENOENT）→ skip 并说明', async () => {
  const dir = withPkg(tempProfile());
  writeFileSync(join(dir, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n');
  const emptyBin = join(dir, 'empty-bin');
  mkdirSync(emptyBin, { recursive: true });
  const result = await withPath(emptyBin, () => run(dir));
  assert.equal(result.skipped, true, JSON.stringify(result));
  assert.match(result.detail, /PM_NOT_FOUND|ENOENT/);
  rmSync(dir, { recursive: true, force: true });
});

test('SP1: npm v7 vulnerabilities 格式也映射真实 severity', () => {
  const parsed = parseAuditJson({
    vulnerabilities: {
      lodash: {
        severity: 'critical',
        via: [{ title: 'Prototype Pollution', url: 'https://example.test/adv' }],
        range: '<4.17.21',
        fixAvailable: true,
      },
      chalk: { severity: 'info', via: ['x'] },
    },
    metadata: { dependencies: { total: 42 }, vulnerabilities: { total: 1 } },
  });
  assert.equal(parsed.auditError, undefined);
  assert.equal(parsed.vulns.length, 1);
  assert.equal(parsed.vulns[0].package, 'lodash');
  assert.equal(parsed.vulns[0].severity, 'critical');
  assert.equal(parsed.totalDependencies, 42);
});

test('SP1: parseAuditJson 识别 error 字段，不误判为无漏洞', () => {
  const parsed = parseAuditJson({ error: { code: 'ENOLOCK', summary: 'requires an existing lockfile' } });
  assert.equal(parsed.auditErrorCode, 'ENOLOCK');
  assert.equal(parsed.vulns, undefined);
});

test('SP1: detectBackend 按锁文件选择 pnpm/npm', () => {
  const dir = withPkg(tempProfile());
  assert.equal(detectBackend(dir), null);
  writeFileSync(join(dir, 'package-lock.json'), '{}');
  assert.equal(detectBackend(dir).pm, 'npm');
  writeFileSync(join(dir, 'pnpm-lock.yaml'), 'lockfileVersion: 9\n');
  assert.equal(detectBackend(dir).pm, 'pnpm', 'pnpm-lock 优先');
  rmSync(dir, { recursive: true, force: true });
});

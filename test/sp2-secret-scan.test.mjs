/**
 * SP2: Secret Scan 测试
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { run } from '../src/checks/sp2-secret-scan.mjs';

function tempProfile() {
  const dir = mkdtempSync(join(tmpdir(), 'dsh-security-sp2-'));
  mkdirSync(join(dir, 'node_modules'), { recursive: true });
  writeFileSync(join(dir, 'package.json'), JSON.stringify({ name: 'test-profile' }));
  return dir;
}

test('SP2: clean profile → pass', async () => {
  const dir = tempProfile();
  writeFileSync(join(dir, 'cordis.patch.yml'), '- id: test\n  name: safe-module\n');
  const result = await run(dir);
  assert.equal(result.ok, true);
  assert.equal(result.id, 'SP2');
  rmSync(dir, { recursive: true, force: true });
});

test('SP2: hardcoded API key → fail', async () => {
  const dir = tempProfile();
  writeFileSync(join(dir, 'cordis.patch.yml'), 'api_key: sk-1234567890abcdef1234567890abcdef\n');
  const result = await run(dir);
  assert.equal(result.ok, false);
  assert.equal(result.severity, 'high');
  assert.ok(result.detail.includes('OpenAI API Key'));
  rmSync(dir, { recursive: true, force: true });
});

test('SP2: env var reference → pass (safe pattern)', async () => {
  const dir = tempProfile();
  writeFileSync(join(dir, 'cordis.patch.yml'), 'api_key: !!js process.env.API_KEY\n');
  const result = await run(dir);
  assert.equal(result.ok, true);
  rmSync(dir, { recursive: true, force: true });
});

test('SP2: PEM private key → fail (critical)', async () => {
  const dir = tempProfile();
  writeFileSync(join(dir, 'key.pem'), '-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n');
  const result = await run(dir);
  assert.equal(result.ok, false);
  assert.equal(result.severity, 'critical');
  rmSync(dir, { recursive: true, force: true });
});

test('SP2: multiple secrets → count correct', async () => {
  const dir = tempProfile();
  writeFileSync(join(dir, 'config.yml'), 'key1: sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\nkey2: ghp_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\n');
  const result = await run(dir);
  assert.equal(result.ok, false);
  assert.ok(result.detail.includes('2'));
  rmSync(dir, { recursive: true, force: true });
});

test('SP2: empty profile → pass', async () => {
  const dir = tempProfile();
  const result = await run(dir);
  assert.equal(result.ok, true);
  rmSync(dir, { recursive: true, force: true });
});

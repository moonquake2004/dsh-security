/**
 * EXT-RED-1: dsh-plugin-reducer integration tests
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { isAvailable, runReducer } from '../src/integrations/plugin-reducer.mjs';

const profileDir = join(tmpdir(), 'dsh security home', 'profiles', 'web');
const invocation = { command: process.execPath, prefixArgs: ['bin.js'], version: '0.3.1' };

function successEnvelope(minimalFailingSet = ['plugin-a', 'plugin-b']) {
  return JSON.stringify({
    schemaVersion: 1,
    tool: { name: 'dsh-plugin-reducer', version: '0.3.1' },
    operation: 'reduce',
    ok: true,
    report: { result: { minimalFailingSet, oneMinimal: true } },
  });
}

test('EXT-RED-1: availability requires a resolvable package CLI', () => {
  assert.equal(isAvailable(() => invocation), true);
  assert.equal(isAvailable(() => ({})), false);
  assert.equal(isAvailable(() => ({ ...invocation, version: '0.3.0' })), false);
  assert.equal(isAvailable(() => { throw new Error('not installed'); }), false);
});

test('EXT-RED-1: a missing optional reducer is skipped with a reason', async () => {
  const result = await runReducer(profileDir, 'web', {
    resolveReducer: () => { throw new Error('not installed'); },
    runCommand: () => assert.fail('must not run'),
  });

  assert.equal(result.ok, true);
  assert.equal(result.skipped, true);
  assert.equal(result.severity, 'low');
  assert.match(result.detail, /not installed/);
});

test('EXT-RED-1: passes every value as a separate non-shell argument', async () => {
  let command;
  let args;
  let spawnOptions;

  const result = await runReducer(profileDir, 'web', {
    dshCommand: 'custom-dsh',
    cwd: join(tmpdir(), 'working directory'),
    resolveReducer: () => ({
      command: process.execPath,
      prefixArgs: [join(tmpdir(), 'package with spaces', 'bin.js')],
      version: '0.3.1',
    }),
    runCommand: (receivedCommand, receivedArgs, receivedOptions) => {
      command = receivedCommand;
      args = receivedArgs;
      spawnOptions = receivedOptions;
      return { status: 0, stdout: successEnvelope(), stderr: '' };
    },
  });

  const resolvedProfile = resolve(profileDir);
  assert.equal(command, process.execPath);
  assert.equal(args[0], join(tmpdir(), 'package with spaces', 'bin.js'));
  assert.equal(args[args.indexOf('--dsh-home') + 1], dirname(dirname(resolvedProfile)));
  assert.equal(args[args.indexOf('--profile') + 1], 'web');
  assert.equal(args[args.indexOf('--probe') + 1], 'web');
  assert.equal(args[args.indexOf('--dsh') + 1], 'custom-dsh');
  assert.equal(spawnOptions.shell, false);
  assert.equal(spawnOptions.timeout, 120_000);
  assert.equal(result.ok, false);
  assert.equal(result.severity, 'medium');
  assert.match(result.detail, /plugin-a, plugin-b/);
  assert.deepEqual(result.evidence.result.minimalFailingSet, ['plugin-a', 'plugin-b']);
});

test('EXT-RED-1: reads only the stable nested minimal set field', async () => {
  const result = await runReducer(profileDir, 'web', {
    resolveReducer: () => invocation,
    runCommand: () => ({
      status: 0,
      stdout: JSON.stringify({
        schemaVersion: 1,
        tool: { name: 'dsh-plugin-reducer', version: '0.3.1' },
        operation: 'reduce',
        ok: true,
        report: {
          minimalSet: ['legacy-wrong-field'],
          result: { minimalFailingSet: ['contract-field'] },
        },
      }),
      stderr: '',
    }),
  });

  assert.match(result.detail, /contract-field/);
  assert.doesNotMatch(result.detail, /legacy-wrong-field/);
});

test('EXT-RED-1: an invalid report is an integration failure, not a pass', async () => {
  const result = await runReducer(profileDir, 'web', {
    resolveReducer: () => invocation,
    runCommand: () => ({ status: 0, stdout: successEnvelope([]), stderr: '' }),
  });

  assert.equal(result.ok, false);
  assert.equal(result.severity, 'low');
  assert.match(result.detail, /invalid report contract/);
});

test('EXT-RED-1: reducer failure envelopes remain visible without becoming security passes', async () => {
  const result = await runReducer(profileDir, 'web', {
    resolveReducer: () => invocation,
    runCommand: () => ({
      status: 1,
      stdout: JSON.stringify({
        schemaVersion: 1,
        tool: { name: 'dsh-plugin-reducer', version: '0.3.1' },
        operation: 'reduce',
        ok: false,
        error: { code: 'FULL_SET_PASSES', message: 'the full plugin set passed' },
      }),
      stderr: '',
    }),
  });

  assert.equal(result.ok, false);
  assert.equal(result.severity, 'low');
  assert.match(result.detail, /FULL_SET_PASSES/);
});

test('EXT-RED-1: rejects an envelope from another reducer version', async () => {
  const result = await runReducer(profileDir, 'web', {
    resolveReducer: () => invocation,
    runCommand: () => ({
      status: 0,
      stdout: JSON.stringify({
        schemaVersion: 1,
        tool: { name: 'dsh-plugin-reducer', version: '0.3.0' },
        operation: 'reduce',
        ok: true,
        report: { result: { minimalFailingSet: ['plugin-a'] } },
      }),
      stderr: '',
    }),
  });

  assert.equal(result.ok, false);
  assert.equal(result.severity, 'low');
  assert.match(result.detail, /unsupported JSON envelope/);
});

test('EXT-RED-1: rejects a path that is not DSH_HOME/profiles/<profile>', async () => {
  const result = await runReducer(join(tmpdir(), 'not-a-profile', 'web'), 'web', {
    resolveReducer: () => invocation,
    runCommand: () => assert.fail('must not run'),
  });

  assert.equal(result.ok, false);
  assert.match(result.detail, /DSH_HOME\/profiles/);
});

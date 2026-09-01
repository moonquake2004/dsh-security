/**
 * dsh-plugin-reducer 集成
 *
 * 在检测到故障时，提供最小化故障插件集的能力。
 * 如果 dsh-plugin-reducer 可由当前项目解析，则执行固定包的 CLI JSON 契约。
 */

import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { basename, dirname, join, resolve } from 'node:path';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { skip } from '../protocol/check.mjs';

const require = createRequire(import.meta.url);
const SUPPORTED_REDUCER_VERSION = '0.3.1';

function validateReducerInvocation(invocation) {
  if (typeof invocation?.command !== 'string' || invocation.command.length === 0
    || !Array.isArray(invocation?.prefixArgs) || invocation.prefixArgs.length === 0
    || invocation.version !== SUPPORTED_REDUCER_VERSION) {
    throw new Error(`installed dsh-plugin-reducer must be version ${SUPPORTED_REDUCER_VERSION}`);
  }
  return invocation;
}

function resolveReducerInvocation() {
  const libraryEntry = require.resolve('dsh-plugin-reducer');
  const packageRoot = dirname(dirname(libraryEntry));
  const manifest = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8'));
  const binEntry = typeof manifest.bin === 'string'
    ? manifest.bin
    : manifest.bin?.['dsh-plugin-reducer'];

  if (manifest.name !== 'dsh-plugin-reducer' || typeof binEntry !== 'string') {
    throw new Error('installed dsh-plugin-reducer package has no supported CLI entry');
  }

  const binPath = resolve(packageRoot, binEntry);
  if (!existsSync(binPath)) {
    throw new Error(`dsh-plugin-reducer CLI entry is missing: ${binPath}`);
  }

  return validateReducerInvocation({
    command: process.execPath,
    prefixArgs: [binPath],
    version: manifest.version,
  });
}

function profileContext(profileDir) {
  if (typeof profileDir !== 'string' || profileDir.trim() === '') {
    throw new TypeError('profileDir must be a non-empty profile directory path');
  }

  const profileDirectory = resolve(profileDir);
  const profilesDirectory = dirname(profileDirectory);
  if (basename(profilesDirectory) !== 'profiles') {
    throw new Error('profileDir must point to DSH_HOME/profiles/<profile>');
  }

  return {
    dshHome: dirname(profilesDirectory),
    profile: basename(profileDirectory),
  };
}

function errorSummary(error) {
  const code = typeof error?.code === 'string' ? `${error.code}: ` : '';
  const message = error instanceof Error ? error.message : String(error);
  return `${code}${message}`.slice(0, 160);
}

function parseEnvelope(stdout, expectedVersion) {
  if (typeof stdout !== 'string' || stdout.trim() === '') {
    throw new TypeError('dsh-plugin-reducer returned no JSON envelope');
  }

  let envelope;
  try {
    envelope = JSON.parse(stdout);
  } catch {
    throw new TypeError('dsh-plugin-reducer returned invalid JSON');
  }

  if (envelope?.schemaVersion !== 1
    || envelope?.tool?.name !== 'dsh-plugin-reducer'
    || envelope?.tool?.version !== expectedVersion) {
    throw new TypeError('dsh-plugin-reducer returned an unsupported JSON envelope');
  }
  return envelope;
}

function envelopeError(envelope, status) {
  const error = new Error(envelope?.error?.message ?? `dsh-plugin-reducer exited with code ${status}`);
  if (typeof envelope?.error?.code === 'string') error.code = envelope.error.code;
  return error;
}

export function isAvailable(resolveReducer = resolveReducerInvocation) {
  try {
    validateReducerInvocation(resolveReducer());
    return true;
  } catch {
    return false;
  }
}

export async function runReducer(profileDir, probeType = 'web', options = {}) {
  const id = 'EXT-RED-1';

  let invocation;
  try {
    invocation = validateReducerInvocation((options.resolveReducer ?? resolveReducerInvocation)());
  } catch (error) {
    return skip(id, Severity.LOW, `dsh-plugin-reducer 未安装或无法解析，跳过故障最小化：${errorSummary(error)}`);
  }

  try {
    const { dshHome, profile } = profileContext(profileDir);
    const args = [
      ...invocation.prefixArgs,
      '--json',
      '--dsh-home', dshHome,
      '--profile', profile,
      '--probe', probeType,
    ];
    if (options.dshCommand ?? process.env.DSH_COMMAND) {
      args.push('--dsh', options.dshCommand ?? process.env.DSH_COMMAND);
    }

    const execution = (options.runCommand ?? spawnSync)(invocation.command, args, {
      encoding: 'utf8',
      timeout: options.overallTimeoutMs ?? 120_000,
      maxBuffer: options.maxBuffer ?? 16 * 1024 * 1024,
      cwd: options.cwd ?? process.cwd(),
      env: options.env ?? process.env,
      windowsHide: true,
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    });

    if (execution.error) throw execution.error;
    const envelope = parseEnvelope(execution.stdout, invocation.version);
    if (execution.status !== 0 || envelope.ok !== true || envelope.operation !== 'reduce') {
      throw envelopeError(envelope, execution.status);
    }

    const report = envelope.report;
    const minimalSet = report?.result?.minimalFailingSet;
    if (!Array.isArray(minimalSet) || minimalSet.length === 0) {
      throw new TypeError('dsh-plugin-reducer returned an invalid report contract');
    }

    return {
      id,
      ok: false,
      severity: Severity.MEDIUM,
      detail: `dsh-plugin-reducer 找到最小故障插件集：${minimalSet.join(', ')}`,
      fix: '移除或禁用故障插件集中的插件',
      evidence: report,
    };
  } catch (error) {
    return {
      id,
      ok: false,
      severity: Severity.LOW,
      detail: `dsh-plugin-reducer 不可用或执行失败：${errorSummary(error)}`,
    };
  }
}

export const pluginReducerCheck = {
  id: 'EXT-RED-1',
  name: 'plugin-reducer',
  severity: Severity.MEDIUM,
  phase: CheckPhase.LIFECYCLE,
  description: 'dsh-plugin-reducer 故障最小化',
  src: 'external',
  source: 'dsh-plugin-reducer',
  runner: (profileDir) => runReducer(profileDir),
};

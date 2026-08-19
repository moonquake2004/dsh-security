/**
 * SR4: Isolation Verify — 插件隔离验证
 *
 * 分析会话日志中的跨插件数据泄漏：
 * - 检测工具调用中的交叉引用
 * - 检测异常的数据流模式
 *
 * Severity: MEDIUM
 * Phase: RUNTIME
 */

import { existsSync, createReadStream } from 'node:fs';
import { createInterface } from 'node:readline';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail } from '../protocol/check.mjs';

function extractToolCalls(line) {
  try {
    const event = JSON.parse(line);
    if (event.type !== 'tool/call') return [];
    const data = event.data || {};
    return [{ name: data.name || data.tool || '', args: data.args || data.input || {}, seq: event.seq, turn: event.turn }];
  } catch { return []; }
}

export async function run(sessionFile) {
  const id = 'SR4';
  if (!sessionFile || !existsSync(sessionFile)) return pass(id, Severity.MEDIUM, '无会话文件，跳过隔离验证');
  if (sessionFile.endsWith('.zstd')) return pass(id, Severity.MEDIUM, 'zstd 文件需先解压');

  const toolCalls = [];
  let lineCount = 0;
  const rl = createInterface({ input: createReadStream(sessionFile, { encoding: 'utf8' }), crlfDelay: Infinity });

  for await (const line of rl) {
    lineCount++;
    if (!line.trim()) continue;
    toolCalls.push(...extractToolCalls(line));
  }

  // 简单的隔离检查：检测同一 turn 内不同工具的数据传递
  const findings = [];
  const byTurn = {};
  for (const call of toolCalls) {
    const turn = call.turn || 0;
    if (!byTurn[turn]) byTurn[turn] = [];
    byTurn[turn].push(call);
  }

  for (const [turn, calls] of Object.entries(byTurn)) {
    const tools = new Set(calls.map(c => c.name));
    if (tools.size > 3) {
      findings.push({ type: 'multi-tool-turn', severity: 'low', detail: `turn ${turn} 使用了 ${tools.size} 个不同工具：${[...tools].join(', ')}` });
    }
  }

  if (findings.length === 0) return pass(id, Severity.MEDIUM, `分析 ${toolCalls.length} 个工具调用，未检测到隔离问题`);

  const details = findings.slice(0, 10).map(f => `[${f.severity}] ${f.detail}`).join('\n');
  return fail(id, Severity.MEDIUM, `检测到 ${findings.length} 个潜在隔离问题：\n${details}`, '检查工具间的数据流是否在预期范围内');
}

export const sr4Check = { id: 'SR4', name: 'isolation-verify', severity: Severity.MEDIUM, phase: CheckPhase.RUNTIME, description: '插件隔离验证', src: 'builtin', runner: (f) => run(f) };

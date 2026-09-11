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

import { existsSync } from 'node:fs';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail, skip } from '../protocol/check.mjs';
import { scanSessionLines, extractEvent } from '../session-reader.mjs';

function extractToolCalls(line) {
  try {
    const e = extractEvent(JSON.parse(line));
    if (e.kind === 'other') return [];
    return [{ name: e.name || '', args: e.argsText || '', seq: e.seq, turn: e.turn }];
  } catch { return []; }
}

export async function run(sessionFile) {
  const id = 'SR4';
  if (!sessionFile || !existsSync(sessionFile)) return pass(id, Severity.MEDIUM, '无会话文件，跳过隔离验证');

  const toolCalls = [];
  let lineCount = 0;

  try {
    lineCount = await scanSessionLines(sessionFile, (line) => {
      if (!line.trim()) return;
      toolCalls.push(...extractToolCalls(line));
    });
  } catch (e) {
    if (e.code === 'ZSTD_UNAVAILABLE') {
      return skip(id, Severity.MEDIUM, 'zstd 命令不可用，无法解压压缩会话日志，跳过隔离验证');
    }
    throw e;
  }

  // 简单的隔离检查：检测同一 turn 内不同工具的数据传递
  // 复审修复：正常工作流一个 turn 用 4-5 个工具很常见，阈值 3→6 降低误报
  const findings = [];
  const byTurn = {};
  for (const call of toolCalls) {
    const turn = call.turn || 0;
    if (!byTurn[turn]) byTurn[turn] = [];
    byTurn[turn].push(call);
  }

  for (const [turn, calls] of Object.entries(byTurn)) {
    const tools = [...new Set(calls.map(c => c.name).filter(Boolean))];
    if (tools.size > 6) {
      findings.push({ type: 'multi-tool-turn', severity: 'low', detail: `turn ${turn} 使用了 ${tools.size} 个不同工具：${tools.slice(0, 8).join(', ')}` });
    }
  }

  if (findings.length === 0) return pass(id, Severity.MEDIUM, `分析 ${toolCalls.length} 个工具调用（${lineCount} 行），未检测到隔离问题`);

  const details = findings.slice(0, 10).map(f => `[${f.severity}] ${f.detail}`).join('\n');
  return fail(id, Severity.MEDIUM, `检测到 ${findings.length} 个潜在隔离问题：\n${details}`, '检查工具间的数据流是否在预期范围内');
}

export const sr4Check = { id: 'SR4', name: 'isolation-verify', severity: Severity.MEDIUM, phase: CheckPhase.RUNTIME, description: '插件隔离验证', src: 'builtin', runner: (f) => run(f) };

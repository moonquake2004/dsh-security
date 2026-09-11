/**
 * SS4: Session Integrity — 会话日志完整性校验
 *
 * 出处：zoahdev/dsh-ecosystem 家族 3（坏工件隔离）+ 家族 11（out-of-tree
 * 会话事件信封缺口）——截断的 tool-call 参数、torn session tail、空文件
 * 会导致会话永久砖化或 resume 失败。
 *
 * 检查项：
 * 1. JSON 语法：逐行 parse，无效行 = 截断/损坏
 * 2. tool/call 配对：每个 tool/call 应有对应 tool/result（孤儿调用）
 * 3. 空/极小文件：0 行或 <10 行 = 可能未正常写入
 *
 * Severity: HIGH
 * Phase: SESSION
 */

import { existsSync, statSync } from 'node:fs';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail, skip } from '../protocol/check.mjs';
import { scanSessionLines, extractEvent } from '../session-reader.mjs';

const MIN_LINES = 10;

export async function run(sessionFile) {
  const id = 'SS4';

  if (!sessionFile || !existsSync(sessionFile)) {
    return skip(id, Severity.HIGH, '无会话日志文件，跳过完整性校验');
  }

  // 检查文件大小
  let fileSize = 0;
  try { fileSize = statSync(sessionFile).size; } catch { /* ignore */ }
  if (fileSize === 0) {
    return fail(id, Severity.HIGH, '会话日志文件为空（0 字节）——可能未正常写入', '检查 dsh 进程是否正常退出；若为预期空会话可忽略', ['#675']);
  }

  let totalLines = 0;
  let invalidJson = 0;
  let firstInvalidLine = null;
  const orphanCalls = new Map(); // callId → { line, turn }
  let maxTurn = -1;
  let resultCount = 0;

  await scanSessionLines(sessionFile, (line, lineNum) => {
    totalLines++;

    // 1. JSON 语法检查
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch {
      invalidJson++;
      if (!firstInvalidLine) firstInvalidLine = lineNum;
      return; // 无法 parse 的行跳过后续检查
    }

    // 2. tool/call 与 tool/result 配对检查（字段路径见 docs/session-shape-v3.md）
    //    v3 中 tool/result 没有 data.callId，id 在 data.message.source.callId —— 旧写法导致 0 配对、
    //    每个调用都被当成孤儿（2026-09 实测：健康会话被报 45 个孤儿）。
    const ev = extractEvent(parsed);
    // maxTurn 必须对**所有**事件更新（无 callId 的事件同样携带 turn），否则 in-flight 豁免判据失效
    if (typeof ev.turn === 'number') maxTurn = Math.max(maxTurn, ev.turn);
    if (ev.callId) {
      if (ev.kind === 'call') orphanCalls.set(ev.callId, { line: lineNum, turn: ev.turn });
      else if (ev.kind === 'result') { orphanCalls.delete(ev.callId); resultCount++; }
    }
  });

  // 3. 极小文件检查
  if (totalLines < MIN_LINES && totalLines > 0) {
    return fail(id, Severity.HIGH,
      `会话日志仅 ${totalLines} 行（阈值 ${MIN_LINES}）——可能未完整记录`,
      '检查会话是否正常结束；若为极短会话可忽略',
      ['#675']
    );
  }

  const issues = [];
  const refs = [];

  // 汇总孤儿 tool/call —— 仅当该调用处在**已闭合的 turn** 中才算真孤儿。
  // 活跃会话的最后一个 turn 天然可能有不配对的调用（正在执行 / 已中断），豁免之（对齐 dsh-doctor S1 的 in-flight 处理）。
  const realOrphans = [...orphanCalls.entries()].filter(([, v]) => typeof v.turn === 'number' && v.turn < maxTurn);
  const inflight = orphanCalls.size - realOrphans.length;
  if (realOrphans.length > 0) {
    const samples = realOrphans.slice(0, 5).map(([id, v]) => `  行${v.line}: callId=${id.slice(0, 16)}…`);
    issues.push(`${realOrphans.length} 个孤儿 tool/call（有调用无结果）：\n${samples.join('\n')}`);
    refs.push('#3234');
  }

  // 汇总无效 JSON
  if (invalidJson > 0) {
    issues.push(`${invalidJson} 行无效 JSON（首个在行 ${firstInvalidLine}）——可能截断或损坏`);
    refs.push('#675', '#1047');
  }

  if (issues.length === 0) {
    return pass(id, Severity.HIGH,
      `会话日志完整性通过：${totalLines} 行，JSON 全有效，${resultCount} 个 tool/result 已配对${inflight > 0 ? `（尾部 in-flight 未配对 ${inflight} 个，属正常）` : ''}`);
  }

  return fail(id, Severity.HIGH,
    `检测到会话日志完整性问题（${totalLines} 行）：\n${issues.join('\n\n')}`,
    '截断的 tool/call 会导致会话砖化（#3234）；无效 JSON 行可能是损坏的事件（#675/#1047）；考虑用 dsh-shelf 归档后重新开始会话',
    refs
  );
}

export const ss4Check = {
  id: 'SS4',
  name: 'session-integrity',
  severity: Severity.HIGH,
  phase: CheckPhase.POST_INSTALL,
  description: '会话日志完整性校验——检测截断 JSON、孤儿 tool/call、空/极小文件（家族 3/11）',
  src: 'builtin',
  runner: (sessionFile) => run(sessionFile),
};

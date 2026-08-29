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
import { scanSessionLines } from '../session-reader.mjs';

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
  const orphanCalls = new Map(); // callId → line number
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

    // 2. tool/call 与 tool/result 配对检查
    const type = parsed.type;
    if (type === 'tool/call') {
      const callId = parsed.data?.callId;
      if (callId) orphanCalls.set(callId, lineNum);
    } else if (type === 'tool/result') {
      const callId = parsed.data?.callId;
      if (callId) {
        orphanCalls.delete(callId); // 配对成功
        resultCount++;
      }
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

  // 汇总孤儿 tool/call
  if (orphanCalls.size > 0) {
    const samples = [...orphanCalls.entries()].slice(0, 5).map(([id, ln]) => `  行${ln}: callId=${id.slice(0, 16)}…`);
    issues.push(`${orphanCalls.size} 个孤儿 tool/call（有调用无结果）：\n${samples.join('\n')}`);
    refs.push('#3234');
  }

  // 汇总无效 JSON
  if (invalidJson > 0) {
    issues.push(`${invalidJson} 行无效 JSON（首个在行 ${firstInvalidLine}）——可能截断或损坏`);
    refs.push('#675', '#1047');
  }

  if (issues.length === 0) {
    return pass(id, Severity.HIGH,
      `会话日志完整性通过：${totalLines} 行，JSON 全有效，${resultCount} 个 tool/result 均已配对`);
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

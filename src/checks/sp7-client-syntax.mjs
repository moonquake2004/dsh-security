/**
 * SP7: Client Bundle Syntax — 插件 client 产物语法预检
 *
 * 出处：deepseek-ai/deepseek-harness discussion #2752 补充案例——插件 client.js
 * 注释未闭合（语法级错误）→ 浏览器端 ReferenceError → Web UI 整页白屏，
 * 服务端 HTTP 200 且日志零感知。P13 只提取 ctx.provide() 服务名，不做语法解析，
 * 这类错误此前完全逃逸离线检查。
 *
 * 做法：对每个已装 DSH 插件包（package.json 含 dsh 字段）的 client 入口产物
 * （<pkg>/client/*.js|mjs、<pkg>/lib/client.js、<pkg>/client.js）执行
 * `node --check`（Node ≥22 自动探测 ESM/CJS，无需区分模块格式）。
 * 解析失败 = boot 前即可断定的必白屏项 → HIGH。
 *
 * Severity: HIGH
 * Phase: POST_INSTALL
 */

import { readFileSync, readdirSync, existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { tmpdir } from 'node:os';
import { execFileSync } from 'node:child_process';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail } from '../protocol/check.mjs';

const CLIENT_EXTENSIONS = ['.js', '.mjs', '.cjs'];
const MAX_FILES_PER_PKG = 10;
const MAX_PKGS = 60;        // 上限只约束"识别为 DSH 插件"的包（普通依赖不占额）
const MAX_TOTAL_FILES = 200; // 全局文件数保险，防病态安装

/** 收集一个插件包内的 client 候选产物 */
function collectClientFiles(pkgDir) {
  const files = [];
  const pushIfClient = (p) => {
    if (files.length >= MAX_FILES_PER_PKG) return;
    if (existsSync(p) && CLIENT_EXTENSIONS.some(ext => p.endsWith(ext))) files.push(p);
  };
  // 形态 A：<pkg>/client/ 目录（真实布局：dsh-doctor、dshmarket 等）
  const clientDir = join(pkgDir, 'client');
  if (existsSync(clientDir)) {
    try {
      for (const e of readdirSync(clientDir, { withFileTypes: true })) {
        if (e.isFile()) pushIfClient(join(clientDir, e.name));
      }
    } catch { /* unreadable dir */ }
  }
  // 形态 B：lib/client.js（真实布局：dsh-better-sidebar、dsh-persist、@xmanrui/dsh-im 等）
  pushIfClient(join(pkgDir, 'lib', 'client.js'));
  // 形态 C：根级 client.js
  pushIfClient(join(pkgDir, 'client.js'));
  return files;
}

/**
 * 对单个文件做语法校验。
 * @returns {{ok: true} | {ok: false, message: string}}
 */
function syntaxCheck(file) {
  try {
    execFileSync(process.execPath, ['--check', file], { timeout: 10000, stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8' });
    return { ok: true };
  } catch (e) {
    const errText = String(e.stderr || e.message || '');
    // 提取最有信息量的一行：SyntaxError/ReferenceError/... 及其位置
    const diagLine = errText.split('\n').find(l => /^(SyntaxError|ReferenceError|TypeError|RangeError|Error)\b/.test(l.trim()));
    const posLine = errText.split('\n').find(l => l.startsWith(file));
    const message = [posLine ? relativeProcess(posLine) : null, diagLine ? diagLine.trim().slice(0, 160) : null]
      .filter(Boolean).join(' — ') || `node --check 失败（exit ${e.status ?? '?'}, ${errText.slice(0, 80)}）`;
    return { ok: false, message };
  }
}

function relativeProcess(posLine) {
  return posLine.replace(/^.*\/node_modules\//, '').slice(0, 120);
}

/** 纯文本版语法校验（供测试与无子进程环境复用）：写入临时 .mjs 不需要——直接用文件路径 */
export async function run(profileDir) {
  const id = 'SP7';
  const nmDir = join(profileDir, 'node_modules');
  if (!existsSync(nmDir)) return pass(id, Severity.HIGH, '无 node_modules，跳过 client 产物语法预检');

  // 枚举已装 DSH 插件包（含 scoped；以 package.json 的 dsh 字段为门控）
  const pkgs = [];
  let entries = [];
  try { entries = readdirSync(nmDir, { withFileTypes: true }); } catch { entries = []; }
  for (const entry of entries) {
    if (!entry.isDirectory() || entry.name.startsWith('.') || entry.name === '.bin') continue;
    if (entry.name.startsWith('@')) {
      let subs = [];
      try { subs = readdirSync(join(nmDir, entry.name), { withFileTypes: true }); } catch { continue; }
      for (const sub of subs) {
        if (sub.isDirectory()) pkgs.push(join(nmDir, entry.name, sub.name));
      }
    } else {
      pkgs.push(join(nmDir, entry.name));
    }
  }

  const findings = [];
  let scannedFiles = 0;
  let scannedPkgs = 0;

  for (const pkgDir of pkgs) {
    const pkgJsonPath = join(pkgDir, 'package.json');
    if (!existsSync(pkgJsonPath)) continue;
    try {
      const pkg = JSON.parse(readFileSync(pkgJsonPath, 'utf8'));
      if (!pkg.dsh) continue; // 只查 DSH 插件包，避免误扫 hono/undici 等普通依赖
    } catch { continue; }
    if (scannedPkgs >= MAX_PKGS) break;
    scannedPkgs++;

    for (const file of collectClientFiles(pkgDir)) {
      if (scannedFiles >= MAX_TOTAL_FILES) break;
      scannedFiles++;
      const result = syntaxCheck(file);
      if (!result.ok) {
        findings.push({
          file: relative(profileDir, file),
          message: result.message,
        });
      }
    }
  }

  if (scannedPkgs === 0) return pass(id, Severity.HIGH, '未发现 DSH 插件包，跳过 client 产物语法预检');
  if (scannedFiles === 0) return pass(id, Severity.HIGH, `扫描 ${scannedPkgs} 个插件包，未发现 client 产物，跳过语法预检`);

  if (findings.length === 0) {
    return pass(id, Severity.HIGH, `语法预检通过：${scannedPkgs} 个插件包 / ${scannedFiles} 个 client 产物均可正常解析`);
  }

  const details = findings.slice(0, 10).map(f => `${f.file}\n    ${f.message}`).join('\n');
  return fail(id, Severity.HIGH,
    `检测到 ${findings.length} 个 client 产物语法错误（boot 后将整页白屏）：\n${details}`,
    '修复对应插件的 client 代码语法错误，或暂时移除该插件；此类错误在浏览器端表现为 Failed to load plugins 白屏且服务端日志无感知',
    ['#2752']
  );
}

export const sp7Check = {
  id: 'SP7',
  name: 'client-syntax',
  severity: Severity.HIGH,
  phase: CheckPhase.POST_INSTALL,
  description: '插件 client 产物语法预检（node --check，boot 前拦截白屏源）',
  src: 'builtin',
  runner: (profileDir) => run(profileDir),
};

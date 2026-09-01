/**
 * SP10: Poison Pattern — 混淆投毒模式检测
 *
 * 出处：dsh-poison-guard（zoahdev）三层检测中的正则层——AST 层需要
 * JS-X-Ray 依赖（零依赖约束下不可用），但高价值的混淆模式可以
 * 用增强正则捕获：
 *
 * 检测模式：
 * - Buffer.from("hex") / Buffer.from("base64") → 去混淆后的 require/import
 * - atob("...") → 隐藏的外发 URL
 * - String.fromCharCode(...) → 去混淆后的命令（curl/wget 等）
 * - eval(...) / new Function(...) → 动态代码执行
 * - Function("return this")() → 全局对象泄漏
 *
 * Severity: HIGH
 * Phase: POST_INSTALL
 */

import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';
import { Severity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail, skip } from '../protocol/check.mjs';

const SCANNABLE_EXT = new Set(['.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx']);
const MAX_FILE_SIZE = 512 * 1024; // 512KB
const MAX_FILES = 200;

/**
 * 混淆投毒检测模式
 * 每个 pattern：{ name, regex, severity, description }
 */
const POISON_PATTERNS = [
  {
    name: 'deobfuscated-import',
    regex: /Buffer\.from\s*\(\s*['"][0-9a-fA-F]{4,}['"]\s*,\s*['"]hex['"]\s*\)/g,
    description: 'Buffer.from(hex) 去混淆 require/import（常见于投毒包隐藏真实依赖）',
  },
  {
    name: 'deobfuscated-base64-import',
    regex: /Buffer\.from\s*\(\s*['"][A-Za-z0-9+/]{8,}={0,2}['"]\s*,\s*['"]base64['"]\s*\)/g,
    description: 'Buffer.from(base64) 去混淆 require/import',
  },
  {
    name: 'hidden-url-atob',
    regex: /(?:atob|btoa)\s*\(\s*['"][A-Za-z0-9+/]{16,}={0,2}['"]\s*\)/g,
    description: 'atob/btoa 隐藏 URL（去混淆后可能是外发 C2 地址）',
  },
  {
    name: 'deobfuscated-command',
    regex: /String\.fromCharCode\s*\(\s*\d{2,3}(?:\s*,\s*\d{2,3}){4,}\s*\)/g,
    description: 'String.fromCharCode 去混淆命令（常见于投毒包隐藏 curl/wget）',
  },
  {
    name: 'eval-execution',
    regex: /(?<!\w)eval\s*\(/g,
    description: 'eval() 动态代码执行（投毒高危信号）',
  },
  {
    name: 'function-constructor',
    regex: /new\s+Function\s*\(/g,
    description: 'new Function() 动态代码构造（投毒高危信号）',
  },
  {
    name: 'global-sandbox-escape',
    regex: /Function\s*\(\s*['"]return\s+this['"]\s*\)\s*\(\s*\)/g,
    description: 'Function("return this")() 全局对象泄漏（沙箱逃逸手段）',
  },
];

/**
 * 递归收集可扫描文件
 */
function collectFiles(dir, files = [], depth = 0) {
  if (depth > 8 || files.length >= MAX_FILES) return files;
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return files; }
  for (const entry of entries) {
    if (files.length >= MAX_FILES) break;
    if (entry.name.startsWith('.') || entry.name === 'node_modules' || entry.name === '.git') continue;
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      collectFiles(fullPath, files, depth + 1);
    } else if (entry.isFile() && SCANNABLE_EXT.has(extname(entry.name).toLowerCase())) {
      try {
        const stat = statSync(fullPath);
        if (stat.size > 0 && stat.size <= MAX_FILE_SIZE) files.push(fullPath);
      } catch { /* skip */ }
    }
  }
  return files;
}

export async function run(profileDir) {
  const id = 'SP10';
  const nmDir = join(profileDir, 'node_modules');
  if (!existsSync(nmDir)) return pass(id, Severity.HIGH, '无 node_modules，跳过投毒模式检测');

  // 枚举 DSH 插件包
  let dirEntries;
  try { dirEntries = readdirSync(nmDir, { withFileTypes: true }); } catch { dirEntries = []; }

  const plugins = [];
  for (const entry of dirEntries) {
    if (plugins.length >= 60) break;
    if (!entry.isDirectory() || entry.name.startsWith('.') || entry.name === '.bin') continue;
    let pkgDirs = [];
    if (entry.name.startsWith('@')) {
      try {
        pkgDirs = readdirSync(join(nmDir, entry.name), { withFileTypes: true })
          .filter(s => s.isDirectory())
          .map(s => join(nmDir, entry.name, s.name));
      } catch { /* skip */ }
    } else {
      pkgDirs = [join(nmDir, entry.name)];
    }
    for (const pd of pkgDirs) {
      const pjPath = join(pd, 'package.json');
      if (!existsSync(pjPath)) continue;
      try {
        const pkg = JSON.parse(readFileSync(pjPath, 'utf8'));
        if (!pkg.dsh) continue;
        plugins.push({ name: pkg.name || entry.name, dir: pd });
      } catch { continue; }
    }
  }

  if (plugins.length === 0) return pass(id, Severity.HIGH, '未发现 DSH 插件包，跳过投毒模式检测');

  const findings = [];
  let scannedFiles = 0;

  for (const plugin of plugins) {
    const files = collectFiles(plugin.dir);
    for (const file of files) {
      scannedFiles++;
      let content;
      try { content = readFileSync(file, 'utf8'); } catch { continue; }

      for (const pattern of POISON_PATTERNS) {
        const matches = content.match(pattern.regex);
        if (matches && matches.length > 0) {
          // 找到匹配行号
          const lines = content.split('\n');
          let matchLine = 1;
          let searchIdx = 0;
          for (let i = 0; i < lines.length; i++) {
            if (content.indexOf(matches[0], searchIdx) < searchIdx + lines[i].length + 1) {
              matchLine = i + 1;
              break;
            }
            searchIdx += lines[i].length + 1;
          }
          findings.push({
            plugin: plugin.name,
            file: file.replace(plugin.dir + '/', ''),
            line: matchLine,
            pattern: pattern.name,
            count: matches.length,
            description: pattern.description,
          });
        }
      }
    }
  }

  if (findings.length === 0) {
    return pass(id, Severity.HIGH,
      `投毒模式检测通过：${plugins.length} 个插件 / ${scannedFiles} 个源文件，未发现混淆投毒特征`);
  }

  // 按 pattern 分组统计
  const byPattern = {};
  for (const f of findings) {
    byPattern[f.pattern] = (byPattern[f.pattern] || 0) + f.count;
  }
  const patternSummary = Object.entries(byPattern).map(([p, c]) => `${p}(${c})`).join(', ');

  const details = findings.slice(0, 10).map(f =>
    `  ${f.plugin}/${f.file}:${f.line} — ${f.pattern} ×${f.count}: ${f.description}`
  ).join('\n');

  return fail(id, Severity.HIGH,
    `检测到 ${findings.length} 处投毒模式命中（${patternSummary}）：\n${details}`,
    '逐一审查命中行：确认是否为合法使用（如 Buffer.from(hex) 在插件中用于解码配置）还是投毒信号；疑似投毒时用 dsh-poison-guard（github.com/zoahdev/dsh-poison-guard）做 AST 级深度扫描',
    ['#2312']
  );
}

export const sp10Check = {
  id: 'SP10',
  name: 'poison-pattern',
  severity: Severity.HIGH,
  phase: CheckPhase.POST_INSTALL,
  description: '混淆投毒模式检测——Buffer.from hex/atob/String.fromCharCode/eval 等（借鉴 dsh-poison-guard regex 层）',
  src: 'builtin',
  runner: (profileDir) => run(profileDir),
};

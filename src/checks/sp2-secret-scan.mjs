/**
 * SP2: Secret Scan — 配置文件硬编码密钥检测
 *
 * 扫描 cordis.patch.yml、package.json 和插件源码中的硬编码密钥。
 * 区分安全模式（环境变量引用）和不安全模式（硬编码值）。
 *
 * Severity: HIGH
 * Phase: POST_INSTALL
 */

import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { Severity, maxSeverity } from '../protocol/severity.mjs';
import { CheckPhase } from '../protocol/phase.mjs';
import { pass, fail } from '../protocol/check.mjs';

/** 密钥模式（正则） */
const SECRET_PATTERNS = [
  { name: 'OpenAI API Key', regex: /sk-[a-zA-Z0-9]{20,}/g, severity: 'high' },
  { name: 'GitHub PAT', regex: /ghp_[a-zA-Z0-9]{36}/g, severity: 'high' },
  { name: 'GitHub Fine-grained PAT', regex: /github_pat_[a-zA-Z0-9_]{20,}/g, severity: 'high' },
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g, severity: 'high' },
  { name: 'Slack Token', regex: /xox[baprs]-[a-zA-Z0-9-]+/g, severity: 'high' },
  { name: 'Google API Key', regex: /AIza[0-9A-Za-z_-]{35}/g, severity: 'high' },
  { name: 'PEM Private Key', regex: /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/g, severity: 'critical' },
  { name: 'Generic Secret Assignment', regex: /(SECRET|TOKEN|API_KEY|PASSWORD|CREDENTIAL)\s*[:=]\s*['"][^'"]{8,}['"]/gi, severity: 'medium' },
];

/** 安全模式（排除） */
const SAFE_PATTERNS = [
  /\$\{[A-Z_]+\}/,           // ${VAR}
  /process\.env\.[A-Z_]+/,   // process.env.VAR
  /!!js\s+process\.env/,     // !!js process.env.XXX (YAML safe)
  /\$env:[A-Z_]+/,           // $env:VAR (PowerShell)
  /os\.environ\[[^]]+\]/,    // os.environ['VAR'] (Python)
];

function isSafePattern(line) {
  return SAFE_PATTERNS.some(p => p.test(line));
}

function scanFile(filePath, profileDir) {
  const findings = [];
  let content;
  try {
    content = readFileSync(filePath, 'utf8');
  } catch {
    return findings;
  }

  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (isSafePattern(line)) continue;

    for (const pattern of SECRET_PATTERNS) {
      const matches = line.matchAll(pattern.regex);
      for (const match of matches) {
        findings.push({
          file: relative(profileDir, filePath),
          line: i + 1,
          type: pattern.name,
          severity: pattern.severity,
          snippet: line.trim().slice(0, 100),
        });
      }
    }
  }
  return findings;
}

function scanDirectory(dir, profileDir, extensions = ['.yml', '.yaml', '.json', '.js', '.mjs', '.ts', '.pem', '.key', '.env', '.toml']) {
  const findings = [];
  if (!existsSync(dir)) return findings;

  const entries = readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    // 点文件默认跳过，但 .env / *.env 是密钥重灾区，必须扫描（复审修复：此前 .env 永不被扫）
    const isEnvFile = entry.name === '.env' || entry.name.endsWith('.env');
    if ((entry.name.startsWith('.') && !isEnvFile) || entry.name === 'node_modules') continue;
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) {
      findings.push(...scanDirectory(fullPath, profileDir, extensions));
    } else if (extensions.some(ext => entry.name.endsWith(ext))) {
      findings.push(...scanFile(fullPath, profileDir));
    }
  }
  return findings;
}

/**
 * SP2 检查：扫描 profile 目录中的硬编码密钥
 * @param {string} profileDir - profile 目录路径
 * @returns {import('../protocol/check.mjs').SecurityCheckResult}
 */
export function run(profileDir) {
  const id = 'SP2';
  const findings = scanDirectory(profileDir, profileDir);

  if (findings.length === 0) {
    return pass(id, Severity.HIGH, '配置文件和插件源码中未检测到硬编码密钥');
  }

  const bySeverity = {};
  for (const f of findings) {
    if (!bySeverity[f.severity]) bySeverity[f.severity] = [];
    bySeverity[f.severity].push(f);
  }

  const summary = Object.entries(bySeverity)
    .map(([sev, items]) => `${sev}: ${items.length}`)
    .join(', ');

  const details = findings
    .slice(0, 10) // 最多显示 10 条
    .map(f => `${f.file}:${f.line} — ${f.type}（${f.severity}）`)
    .join('\n');

  const fix = '将密钥移至环境变量或密钥管理器（如 1Password），从配置文件中删除硬编码值。使用 !!js process.env.VAR 引用环境变量。';
  const overallSeverity = maxSeverity(findings.map(f => f.severity));

  return fail(id, overallSeverity, `检测到 ${findings.length} 个硬编码密钥（${summary}）：\n${details}`, fix, ['#962']);
}

export const sp2Check = {
  id: 'SP2',
  name: 'secret-scan',
  severity: Severity.HIGH,
  phase: CheckPhase.POST_INSTALL,
  description: '配置文件和插件源码中的硬编码密钥检测',
  src: 'builtin',
  runner: (profileDir) => Promise.resolve(run(profileDir)),
};

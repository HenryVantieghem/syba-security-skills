#!/usr/bin/env node
// SYBA secret hygiene: find secrets and personal data before they are committed,
// pushed, published, pasted into a chat or sent to an AI model. Redact them on request.
//
//   node secret-scan.mjs [path ...]          scan files (git-tracked + untracked-not-ignored inside a repo)
//   node secret-scan.mjs --staged            scan only lines added in the staged diff (pre-commit)
//   node secret-scan.mjs --diff <ref>        scan lines added since <ref> (e.g. origin/main)
//   node secret-scan.mjs --history           scan every line ever added in git history (pre-publish)
//   node secret-scan.mjs --redact <file|->   print the text with every secret replaced by [redacted:<kind>]
//   flags: --json  --emails (also flag email addresses)  --all (include lockfiles and minified files)
//
// Card numbers (Luhn-checked), IBANs (mod-97-checked), US SSNs and token shapes come from
// the SYBA Shield extension's redaction layer (lib/ask-redact.js); the vendor key shapes
// are added here. Matches are never printed in full.
// A line containing "syba-secret-ok" or "gitleaks:allow" is skipped (for known test fixtures).
//
// Exit code: 0 nothing found, 10 only medium findings, 20 at least one high finding.

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import './engine/ask-redact.js';
import { exitCodeFor, readInput } from './engine/verdict.js';

const R = globalThis.SYBA_ASK_REDACT;

// [kind, severity, regex]. Each is a shape a real credential has, not a keyword.
export const RULES = [
  ['private-key', 'high', /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g],
  ['aws-access-key-id', 'high', /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g],
  ['aws-secret-access-key', 'high', /\baws_?secret_?access_?key\b\s*[:=]\s*["']?[A-Za-z0-9/+]{40}\b/gi],
  ['google-api-key', 'high', /\bAIza[0-9A-Za-z_-]{35}\b/g],
  ['gcp-service-account', 'high', /"private_key_id"\s*:\s*"[a-f0-9]{40}"/g],
  ['github-token', 'high', /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g],
  ['gitlab-token', 'high', /\bglpat-[A-Za-z0-9_-]{20,}\b/g],
  ['anthropic-key', 'high', /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{40,}\b/g],
  ['openai-key', 'high', /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b|\bsk-proj-[A-Za-z0-9_-]{40,}\b/g],
  ['stripe-key', 'high', /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b/g],
  ['stripe-webhook-secret', 'high', /\bwhsec_[A-Za-z0-9]{24,}\b/g],
  ['slack-token', 'high', /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g],
  ['slack-webhook', 'high', /https:\/\/hooks\.slack\.com\/(?:services|workflows)\/[A-Za-z0-9/_-]{20,}/g],
  ['discord-webhook', 'high', /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]{30,}/g],
  ['npm-token', 'high', /\bnpm_[A-Za-z0-9]{36}\b/g],
  ['pypi-token', 'high', /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}\b/g],
  ['sendgrid-key', 'high', /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g],
  ['twilio-key', 'medium', /\bSK[0-9a-f]{32}\b/g],
  ['huggingface-token', 'high', /\bhf_[A-Za-z0-9]{34,}\b/g],
  ['telegram-bot-token', 'high', /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g],
  ['jwt', 'medium', /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g],
  ['password-in-url', 'high', /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|ftp|smtp):\/\/[^\s:/@"']+:[^\s@/"']{3,}@[^\s"']+/gi],
];

// password = "…", API_KEY: '…' and friends. Medium: needs a human look.
const ASSIGNMENT = /\b([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key))\b["']?\s*[:=]\s*["']([^"'\s]{10,})["']/gi;
const PLACEHOLDER = /^(?:x+$|\*+$|\.+$|<[^>]*>|\$\{[^}]*\}|\{\{[^}]*\}\}|%[A-Z_]+%|your[_-]|changeme|change[_-]me|example|placeholder|dummy|test|sample|redacted|todo|none|null|undefined|process\.env|os\.environ|env\(|getenv)/i;

const SKIP_DIRS = new Set(['.git', 'node_modules', 'vendor', 'dist', 'build', '.next', '.venv', 'venv', '__pycache__', 'target', '.turbo', 'coverage', 'DerivedData', 'Pods']);
const NOISY_FILE = /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|Cargo\.lock|poetry\.lock|uv\.lock|Gemfile\.lock|composer\.lock|go\.sum|Podfile\.lock)$|\.min\.(?:js|css)$|\.map$/;
const BINARY_EXT = /\.(?:png|jpe?g|gif|webp|ico|icns|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|class|so|dylib|dll|exe|bin|wasm|woff2?|ttf|otf|eot|mp[34]|mov|avi|webm|wav|ogg|psd|sketch|fig|sqlite|db|pyc|o|a)$/i;
const ALLOW_MARK = /syba-secret-ok|gitleaks:allow/;
const ENV_FILE = /(?:^|\/)\.env(?:\.[\w-]+)?$/;

function entropy(s) {
  const f = {};
  for (const c of s) f[c] = (f[c] || 0) + 1;
  return Object.values(f).reduce((h, n) => h - (n / s.length) * Math.log2(n / s.length), 0);
}

export function mask(s) {
  const t = String(s);
  if (t.length <= 8) return `${'*'.repeat(t.length)}`;
  return `${t.slice(0, 4)}…(${t.length} chars)`;
}

const CARD_IIN = /^(?:4\d|5[1-5]|2[2-7]|3[47]|6(?:011|5\d)|35)/;

/** Every secret or personal-data span in one string. */
export function findSecrets(text, { emails = false } = {}) {
  const src = String(text || '');
  const out = [];
  for (const [kind, severity, re] of RULES) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(src))) out.push({ kind, severity, start: m.index, end: m.index + m[0].length });
  }
  ASSIGNMENT.lastIndex = 0;
  let a;
  while ((a = ASSIGNMENT.exec(src))) {
    const val = a[2];
    if (PLACEHOLDER.test(val) || entropy(val) < 3.2 || /^[a-z]+$/i.test(val)) continue;
    const start = a.index + a[0].lastIndexOf(val);
    out.push({ kind: 'hardcoded-secret', severity: 'medium', start, end: start + val.length, name: a[1] });
  }
  // SYBA's redaction layer: Luhn-valid cards, mod-97 IBANs, SSNs, token shapes.
  for (const s of R.findSensitive(src, { emails })) {
    const val = src.slice(s.start, s.end);
    if (s.kind === 'card') {
      const digits = val.replace(/[ -]/g, '');
      const before = src[s.start - 1] || '', after = src[s.end] || '';
      if (!CARD_IIN.test(digits) || /[A-Za-z0-9_.]/.test(before) || /[A-Za-z0-9_]/.test(after)) continue;
    }
    out.push({ kind: s.kind === 'secret' ? 'api-token' : s.kind, severity: s.kind === 'email' ? 'medium' : 'high', start: s.start, end: s.end });
  }
  // One finding per span: keep the most specific (first-listed) kind.
  out.sort((x, y) => x.start - y.start || (y.end - y.start) - (x.end - x.start));
  const merged = [];
  for (const f of out) {
    const last = merged[merged.length - 1];
    if (last && f.start < last.end) { if (f.end > last.end) last.end = f.end; continue; }
    merged.push({ ...f });
  }
  return merged;
}

export function redact(text, opts) {
  const src = String(text || '');
  let res = '', at = 0;
  for (const f of findSecrets(src, opts)) { res += src.slice(at, f.start) + `[redacted:${f.kind}]`; at = f.end; }
  return res + src.slice(at);
}

/** Scan text line by line. `where` labels the source (file path or commit). */
export function scanText(text, where, opts = {}, lineOffset = 0) {
  const findings = [];
  const lines = String(text).split('\n');
  lines.forEach((line, i) => {
    if (ALLOW_MARK.test(line) || line.length > 20000) return;
    for (const f of findSecrets(line, opts)) {
      findings.push({ file: where, line: i + 1 + lineOffset, kind: f.kind, severity: f.severity, preview: mask(line.slice(f.start, f.end)) });
    }
  });
  return findings;
}

function git(args, cwd) {
  return execFileSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 1024 * 1024 * 512, stdio: ['ignore', 'pipe', 'ignore'] });
}

function listFiles(target, all) {
  const abs = path.resolve(target);
  const stat = fs.statSync(abs);
  if (stat.isFile()) return [abs];
  try {
    const out = git(['ls-files', '-co', '--exclude-standard', '-z'], abs);
    return out.split('\0').filter(Boolean).map((f) => path.join(abs, f)).filter((f) => all || !NOISY_FILE.test(f));
  } catch { /* not a git repo: walk */ }
  const files = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(path.join(dir, e.name)); }
      else if (e.isFile()) { const p = path.join(dir, e.name); if (all || !NOISY_FILE.test(p)) files.push(p); }
    }
  };
  walk(abs);
  return files;
}

export function scanPaths(targets, opts = {}) {
  const findings = [];
  let scanned = 0;
  for (const t of targets) {
    for (const file of listFiles(t, opts.all)) {
      const rel = path.relative(process.cwd(), file) || file;
      if (ENV_FILE.test(file) && !/\.(?:example|sample|template|dist)$/i.test(file)) {
        findings.push({ file: rel, line: 0, kind: 'env-file', severity: 'medium', preview: 'a .env file is tracked or not ignored; add it to .gitignore' });
      }
      if (BINARY_EXT.test(file)) continue;
      let buf;
      try { buf = fs.readFileSync(file); } catch { continue; }
      if (buf.length > 5 * 1024 * 1024 || buf.subarray(0, 8000).includes(0)) continue;
      scanned += 1;
      findings.push(...scanText(buf.toString('utf8'), rel, opts));
    }
  }
  return { findings, scanned };
}

/** Lines added in a unified diff (git diff -U0 / git log -p). */
export function scanDiff(diff, opts = {}) {
  const findings = [];
  let file = '', commit = '', line = 0;
  for (const l of String(diff).split('\n')) {
    if (l.startsWith('commit ')) { commit = l.slice(7, 19); continue; }
    if (l.startsWith('+++ ')) { file = l.replace(/^\+\+\+ (?:b\/)?/, ''); continue; }
    const h = l.match(/^@@ -\d+(?:,\d+)? \+(\d+)/);
    if (h) { line = Number(h[1]); continue; }
    if (l.startsWith('+') && !l.startsWith('+++')) {
      if (opts.all || !NOISY_FILE.test(file)) {
        for (const f of scanText(l.slice(1), file, opts)) findings.push({ ...f, line, ...(commit ? { commit } : {}) });
      }
      line += 1;
    }
  }
  return findings;
}

async function main(argv) {
  const json = argv.includes('--json');
  const opts = { emails: argv.includes('--emails'), all: argv.includes('--all') };
  const valueOf = (flag) => { const i = argv.indexOf(flag); return i === -1 ? undefined : argv[i + 1]; };
  if (argv.includes('--redact')) {
    process.stdout.write(redact(await readInput(valueOf('--redact') ?? '-'), opts));
    return;
  }
  let findings, scanned = null, mode;
  if (argv.includes('--staged')) { mode = 'staged diff'; findings = scanDiff(git(['diff', '--cached', '-U0', '--no-color'], process.cwd()), opts); }
  else if (argv.includes('--diff')) { mode = `diff since ${valueOf('--diff')}`; findings = scanDiff(git(['diff', '-U0', '--no-color', valueOf('--diff')], process.cwd()), opts); }
  else if (argv.includes('--history')) { mode = 'full git history'; findings = scanDiff(git(['log', '-p', '-U0', '--all', '--no-color', '--format=commit %H'], process.cwd()), opts); }
  else {
    const skip = new Set(['--diff', '--redact']);
    const targets = argv.filter((a, i) => !a.startsWith('--') && !skip.has(argv[i - 1]));
    mode = 'files';
    ({ findings, scanned } = scanPaths(targets.length ? targets : ['.'], opts));
  }
  const level = findings.some((f) => f.severity === 'high') ? 'stop' : findings.length ? 'careful' : 'safe';
  if (json) process.stdout.write(JSON.stringify({ mode, scanned, count: findings.length, findings }, null, 2) + '\n');
  else {
    const head = findings.length
      ? `Stop: ${findings.length} possible secret${findings.length === 1 ? '' : 's'} or personal data found (${mode}${scanned != null ? `, ${scanned} files` : ''}).`
      : `Safe: no secrets found (${mode}${scanned != null ? `, ${scanned} files` : ''}).`;
    const lines = [level === 'careful' ? head.replace(/^Stop/, 'Be careful') : head];
    for (const f of findings.slice(0, 200)) lines.push(`  - [${f.severity}] ${f.kind} at ${f.file}${f.line ? `:${f.line}` : ''}${f.commit ? ` (commit ${f.commit})` : ''}: ${f.preview}`);
    if (findings.length > 200) lines.push(`  … and ${findings.length - 200} more (use --json)`);
    if (findings.length) lines.push('Next step: do not commit, push or publish. Move each value to an environment variable or secret store, rotate any real key that was ever committed or shared, and rewrite history if it was pushed.');
    process.stdout.write(lines.join('\n') + '\n');
  }
  process.exit(exitCodeFor(level));
}

if (process.argv[1]?.endsWith('secret-scan.mjs')) main(process.argv.slice(2));

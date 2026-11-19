#!/usr/bin/env node
// SYBA security review helper: flag the lines in a web-app change that a reviewer must
// look at, grouped by the review checklist (auth, injection, XSS, secrets, CSP and headers,
// cookies and CORS, crypto, file and network access, dependencies).
//
//   node review-scan.mjs                 lines added vs the default branch (or HEAD~1)
//   node review-scan.mjs --diff <ref>    lines added since <ref>
//   node review-scan.mjs --staged        lines added in the staged diff
//   node review-scan.mjs <file ...>      whole files
//   flags: --json
//
// These are pointers for a human-quality review, not verdicts: each hit names the
// question to answer. Exit code: 0 nothing flagged, 10 something to check, 20 a high hit.

import fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { exitCodeFor } from './engine/verdict.js';

// [category, severity, id, regex, question]
export const CHECKS = [
  ['Injection', 'high', 'sql_concat', /\b(?:query|execute|exec|raw|prepare|sql)\s*\(\s*(?:`[^`]*\$\{|["'][^"']*["']\s*\+|f["'][^"']*\{)|\b(?:SELECT|INSERT|UPDATE|DELETE)\b[^;\n]{0,80}(?:["'`]\s*\+\s*\w|\$\{\w)/i, 'Is user input concatenated into SQL? Use parameterised queries.'],
  ['Injection', 'high', 'shell_exec', /\b(?:child_process\.)?exec(?:Sync)?\s*\(\s*(?:`[^`]*\$\{|[^)]*\+)|\bos\.system\s*\(|\bsubprocess\.\w+\([^)]*shell\s*=\s*True|\bshell_exec\s*\(|\bRuntime\.getRuntime\(\)\.exec/, 'Can a request value reach a shell command? Pass an argument array, never a string.'],
  ['Injection', 'high', 'eval', /\beval\s*\(|\bnew\s+Function\s*\(|\bsetTimeout\s*\(\s*["'`]|\bvm\.runIn|\bpickle\.loads?\(|\byaml\.load\((?![^)]*SafeLoader)|\bunserialize\s*\(|\bMarshal\.load/, 'Does this evaluate or deserialise data an attacker can influence?'],
  ['Injection', 'medium', 'nosql', /\$where|\.find\(\s*(?:req|request)\.(?:body|query|params)/, 'Is a request object passed straight into a NoSQL query (operator injection)?'],
  ['Injection', 'medium', 'path_traversal', /(?:readFile|createReadStream|sendFile|open|unlink|writeFile)\w*\s*\([^)]*(?:req|request|params|query|body)\b/, 'Can a request value choose a file path? Resolve it and check it stays inside the allowed folder.'],
  ['Injection', 'medium', 'ssrf', /\b(?:fetch|axios(?:\.\w+)?|got|request|http\.get|https\.get|requests\.(?:get|post)|urlopen)\s*\(\s*(?:req|request|params|query|body|url\b|userUrl|input)/, 'Can a user make the server fetch any URL (SSRF)? Allowlist hosts and block private IPs and cloud metadata.'],
  ['XSS', 'high', 'raw_html', /dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML|document\.write\s*\(|v-html\s*=|\{@html\s|\|\s*safe\b|mark_safe\s*\(|Markup\s*\(|html_safe|<%-|\{\{\{/, 'Is this HTML built from user data? Sanitise (e.g. DOMPurify) or render as text.'],
  ['XSS', 'medium', 'js_url', /href\s*=\s*\{?\s*(?:user|props|data|item)\.|javascript:/i, 'Can a user-supplied link be a javascript: URL? Allow only http(s).'],
  ['Auth', 'high', 'jwt_none', /algorithms?\s*:\s*\[?\s*["']none["']|verify\s*:\s*false|jwt\.decode\s*\((?![^)]*verify)|ignoreExpiration\s*:\s*true/i, 'Is a token decoded without verifying its signature or expiry?'],
  ['Auth', 'medium', 'route_without_auth', /\b(?:app|router)\.(?:post|put|patch|delete)\s*\(\s*["'`][^"'`]*(?:admin|user|account|delete|payment|billing|role|invite|settings)/i, 'Does this state-changing route check that the caller is signed in AND allowed to act on this object (not just any signed-in user)?'],
  ['Auth', 'medium', 'idor', /(?:findById|findOne|get|where)\s*\(\s*(?:req|request)\.(?:params|query|body)\.\w*id\b/i, 'Is the object fetched by an ID from the request checked against the current user (IDOR)?'],
  ['Auth', 'medium', 'weak_compare', /(?:token|secret|signature|hmac|password)\w*\s*===?\s*\w+|\w+\s*===?\s*(?:token|secret|signature|hmac)\b/i, 'Comparing secrets with == leaks timing; use a constant-time compare.'],
  ['Secrets', 'high', 'client_secret', /(?:NEXT_PUBLIC_|VITE_|REACT_APP_|EXPO_PUBLIC_|PUBLIC_)\w*(?:SECRET|PRIVATE|SERVICE_ROLE|SK_|API_KEY)\w*/, 'A secret in a public env var ships to every browser. Keep it server-side.'],
  ['Secrets', 'high', 'service_role', /service_role|SUPABASE_SERVICE|sk_live_|serviceAccountKey/, 'Is a privileged key used in code that runs in the browser or app?'],
  ['Headers', 'medium', 'csp_unsafe', /unsafe-inline|unsafe-eval|script-src[^;"']*\*|default-src[^;"']*\*/, 'This Content-Security-Policy allows inline/eval or any host, which undoes most XSS protection.'],
  ['Headers', 'medium', 'headers_off', /helmet\(\s*\{[^}]*contentSecurityPolicy\s*:\s*false|X-Frame-Options["']?\s*[:,]\s*["']?ALLOW|frame-ancestors\s+\*/i, 'Are security headers being switched off?'],
  ['Cookies/CORS', 'high', 'cors_any_credentials', /origin\s*:\s*(?:true|["']\*["'])[^}]*credentials\s*:\s*true|Access-Control-Allow-Origin["']?\s*[:,]\s*["']?\*[^\n]*credentials/i, 'Any origin plus credentials lets every site act as the signed-in user.'],
  ['Cookies/CORS', 'medium', 'cors_any', /Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*|cors\(\s*\)|origin\s*:\s*["']\*["']/, 'Open CORS: fine for public data only. Is any private data or cookie-authenticated route behind it?'],
  ['Cookies/CORS', 'medium', 'cookie_flags', /(?:httpOnly|httponly)\s*:\s*false|secure\s*:\s*false|sameSite\s*:\s*["']?none|SESSION_COOKIE_SECURE\s*=\s*False/i, 'Session cookies need HttpOnly, Secure and SameSite=Lax or Strict.'],
  ['Crypto', 'medium', 'weak_crypto', /createHash\(\s*["'](?:md5|sha1)["']|hashlib\.(?:md5|sha1)\(|\bDES\b|ECB|Math\.random\(\)[^\n]*(?:token|secret|password|id|key|otp|code)/i, 'Weak hash or non-random token. Use bcrypt/argon2 for passwords and crypto.randomBytes / secrets for tokens.'],
  ['Crypto', 'high', 'tls_off', /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*["']?0|verify\s*=\s*False|InsecureSkipVerify\s*:\s*true/, 'TLS certificate checking is turned off.'],
  ['Data', 'medium', 'logging_secrets', /console\.log\([^)]*(?:password|token|secret|authorization|cookie|card)|logger\.\w+\([^)]*(?:password|token|secret)/i, 'Does this log a password, token or personal data?'],
  ['Data', 'medium', 'open_redirect', /res\.redirect\(\s*(?:req|request)\.|redirect\(\s*request\.(?:args|GET)|location\.href\s*=\s*(?:params|query|new URLSearchParams)/, 'Can a user choose where this redirects (open redirect, used in phishing)? Allow only relative paths or listed hosts.'],
  ['Data', 'medium', 'upload', /multer\(|upload\.single|FileField|request\.files|formidable/, 'File upload: is type checked by content, size capped, and the file stored outside the web root with a generated name?'],
  ['Data', 'medium', 'mass_assignment', /(?:create|update|insert)\w*\(\s*(?:req|request)\.body\s*\)|Object\.assign\(\s*\w+\s*,\s*(?:req|request)\.body/, 'Is the whole request body written to the database (mass assignment of role, isAdmin, price)?'],
  ['Data', 'medium', 'rate_limit', /\/(?:login|signin|sign-in|otp|verify|reset-password|forgot)/i, 'Is this sign-in / code endpoint rate limited and does it avoid revealing whether an account exists?'],
  ['AI', 'medium', 'llm_tool_exec', /tool_choice|function_call|tools\s*:\s*\[|\.run_tool|execute_tool/, 'Can text from a web page, email or document reach this model and make it call a tool? Treat that content as data and confirm consequential actions.'],
];

function git(args) {
  return execFileSync('git', args, { encoding: 'utf8', maxBuffer: 1024 * 1024 * 256, stdio: ['ignore', 'pipe', 'ignore'] });
}

function defaultBase() {
  for (const ref of ['origin/main', 'origin/master', 'main', 'master']) {
    try {
      const base = git(['merge-base', 'HEAD', ref]).trim();
      if (base && base !== git(['rev-parse', 'HEAD']).trim()) return base;
    } catch { /* try next */ }
  }
  return 'HEAD~1';
}

const SKIP_FILE = /(?:^|\/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?)$|\.(?:min\.js|map|md|png|jpe?g|svg|lock)$|(?:^|\/)(?:test|tests|__tests__|spec)\//;

export function scanLines(lines) {
  const hits = [];
  for (const { file, line, text } of lines) {
    if (SKIP_FILE.test(file) || text.length > 2000) continue;
    for (const [category, severity, id, re, question] of CHECKS) {
      if (re.test(text)) hits.push({ category, severity, id, file, line, code: text.trim().slice(0, 160), question });
    }
  }
  return hits;
}

export function addedLines(diff) {
  const out = [];
  let file = '', line = 0;
  for (const l of String(diff).split('\n')) {
    if (l.startsWith('+++ ')) { file = l.replace(/^\+\+\+ (?:b\/)?/, ''); continue; }
    const h = l.match(/^@@ -\d+(?:,\d+)? \+(\d+)/);
    if (h) { line = Number(h[1]); continue; }
    if (l.startsWith('+') && !l.startsWith('+++')) { out.push({ file, line, text: l.slice(1) }); line += 1; }
  }
  return out;
}

async function main(argv) {
  const json = argv.includes('--json');
  const vi = (f) => { const i = argv.indexOf(f); return i === -1 ? undefined : argv[i + 1]; };
  const files = argv.filter((a, i) => !a.startsWith('--') && argv[i - 1] !== '--diff');
  let lines, scope;
  if (files.length) {
    scope = `${files.length} file(s)`;
    lines = files.flatMap((f) => fs.readFileSync(f, 'utf8').split('\n').map((text, i) => ({ file: f, line: i + 1, text })));
  } else if (argv.includes('--staged')) {
    scope = 'staged changes';
    lines = addedLines(git(['diff', '--cached', '-U0', '--no-color']));
  } else {
    const base = vi('--diff') || defaultBase();
    scope = `changes since ${base.slice(0, 12)}`;
    lines = addedLines(git(['diff', '-U0', '--no-color', base]));
  }
  const hits = scanLines(lines);
  const level = hits.some((h) => h.severity === 'high') ? 'stop' : hits.length ? 'careful' : 'safe';
  if (json) process.stdout.write(JSON.stringify({ scope, linesScanned: lines.length, hits }, null, 2) + '\n');
  else {
    const out = [`${hits.length} line(s) to check in ${scope} (${lines.length} lines scanned).`];
    const byCat = {};
    for (const h of hits) (byCat[h.category] ||= []).push(h);
    for (const [cat, list] of Object.entries(byCat)) {
      out.push(`\n${cat}`);
      for (const h of list.slice(0, 40)) out.push(`  - [${h.severity}] ${h.file}:${h.line} ${h.id}: ${h.question}\n      ${h.code}`);
    }
    process.stdout.write(out.join('\n') + '\n');
  }
  process.exit(exitCodeFor(level));
}

if (process.argv[1]?.endsWith('review-scan.mjs')) main(process.argv.slice(2));

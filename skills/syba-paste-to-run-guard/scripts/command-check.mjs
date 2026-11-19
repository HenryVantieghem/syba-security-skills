#!/usr/bin/env node
// SYBA paste-to-run guard: check a shell / PowerShell / Run-dialog command BEFORE it runs.
// Catches ClickFix ("paste this into Terminal to verify you are human"), download-and-run
// one-liners from odd hosts, base64-decoded execution, reverse shells, credential theft,
// persistence and destructive commands.
//
//   node command-check.mjs "<command>" [--context <file|text>] [--json]
//   echo "<command>" | node command-check.mjs - [--context page.txt]
//
// --context is the page, message or README text that told you to run it. The ClickFix
// detector (the SYBA Shield extension's clipboard-exec-signals.js) needs both legs: an
// execution-shaped command AND text telling a person to paste and run it.
//
// Exit code: 0 Safe, 10 Be careful, 20 Stop.

import './engine/clipboard-exec-signals.js';
import { urlHeuristics, verdictFromScore, getRegistrableDomain } from './engine/heuristics.js';
import { levelOf, worst, exitCodeFor, readInput, LABEL } from './engine/verdict.js';

const CLIP = globalThis.SYBA_CLIPBOARD_EXEC;

// Official installer hosts that publish `curl … | sh` as their documented install.
// A pipe-to-shell from one of these is normal developer documentation.
export const KNOWN_INSTALLERS = new Set([
  'bun.sh', 'deno.land', 'sh.rustup.rs', 'rustup.rs', 'get.docker.com', 'brew.sh', 'astral.sh',
  'install.python-poetry.org', 'get.pnpm.io', 'fnm.vercel.app', 'starship.rs', 'ollama.com',
  'claude.ai', 'cli.github.com', 'sdkman.io', 'get.sdkman.io', 'nixos.org', 'install.determinate.systems',
  'get.helm.sh', 'get.k3s.io', 'tailscale.com', 'fly.io', 'railway.app', 'supabase.com', 'volta.sh',
  'opencode.ai', 'mise.run', 'pixi.sh', 'foundry.paradigm.xyz', 'raw.githubusercontent.com',
]);
// raw.githubusercontent.com is only trusted for these orgs' paths.
const TRUSTED_RAW_ORGS = new Set(['homebrew', 'nvm-sh', 'ohmyzsh', 'creationix', 'rvm', 'pyenv', 'golangci', 'helm', 'kubernetes', 'microsoft', 'docker', 'anthropics', 'openai', 'denoland', 'oven-sh']);

const URL_RE = /\b(?:https?|ftp):\/\/[^\s"'`|;&)<>]+/gi;
const IP_HOST = /^\d{1,3}(?:\.\d{1,3}){3}$/;

const RULES = [
  // [id, level, message, regex]
  ['reverse_shell', 'stop', 'Opens a reverse shell: it hands control of this machine to a remote host.', /\/dev\/tcp\/|\bnc(?:at)?\b[^\n|]*\s-(?:e|c)\s|\bsocat\b[^\n]*exec:|\bbash\s+-i\s*>&|\bpython3?\b[^\n]*socket[^\n]*(?:subprocess|pty\.spawn)|\bmkfifo\b[^\n]*\bnc\b/i],
  ['secret_exfil', 'stop', 'Reads keys, passwords or browser data and sends them off this machine.', /(?:\.ssh\/id_|\.aws\/credentials|\.env\b|keychain|login\.keychain|security\s+(?:find|dump)-(?:generic|internet)-password|security\s+dump-keychain|Cookies|Login Data|\.npmrc|\.git-credentials|\.docker\/config\.json|wallet\.dat|Local State)[^\n]*\|\s*(?:curl|wget|nc|base64)|(?:curl|wget)\b[^\n]*(?:-d|--data|-F|--upload-file|-T)\s*@?[^\s]*(?:\.ssh|\.aws|keychain|Cookies|Login Data|\.env)/i],
  ['keychain_dump', 'stop', 'Dumps saved passwords from the macOS keychain.', /\bsecurity\s+(?:dump-keychain|find-(?:generic|internet)-password\b[^\n]*\s-[wg]\b)/i],
  ['decode_and_run', 'stop', 'Decodes a hidden (base64/hex) payload and runs it, so you cannot see what it does.', /(?:base64\s+(?:-d|--decode|-D)|openssl\s+(?:base64|enc)\s+-d|xxd\s+-r|frombase64string|\[convert\]::frombase64|atob\()[^\n]*?(?:\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|\|\s*(?:python3?|perl|ruby|node|osascript)\b|\biex\b|invoke-expression|\beval\b)|\beval\s*["'(]?\s*\$\(\s*(?:echo|printf)[^)]*\|\s*base64/i],
  ['powershell_hidden_download', 'stop', 'PowerShell that downloads and runs code in a hidden window.', /\b(?:powershell|pwsh)\b[^\n]*(?:-w(?:indowstyle)?\s+h(?:idden)?|-enc(?:odedcommand)?\s)/i],
  ['mshta_lolbin', 'stop', 'Uses a Windows system tool (mshta, rundll32, regsvr32, certutil, bitsadmin) to fetch or run code: a classic ClickFix payload.', /\b(?:mshta|rundll32|regsvr32|certutil|bitsadmin|cscript|wscript)(?:\.exe)?\b[^\n]*(?:https?:|\\\\|-urlcache|\/transfer|javascript:|scrobj)/i],
  ['destructive', 'stop', 'Deletes or overwrites everything in a home folder, the whole disk or the system.', /\brm\s+-[a-z]*r[a-z]*f?[a-z]*\s+(?:--no-preserve-root\s+)?(?:\/|~|\$HOME|\/\*|~\/\*)(?:\s|$)|\bmkfs\.|\bdd\b[^\n]*\bof=\/dev\/(?:disk|sd|nvme)|:\(\)\s*\{\s*:\|:&\s*\};:|\bdiskutil\s+(?:erase|zero)/i],
  ['quarantine_strip', 'careful', 'Removes macOS Gatekeeper quarantine, so an unsigned download runs without the usual warning.', /\bxattr\s+(?:-[a-z]*d[a-z]*\s+com\.apple\.quarantine|-c|-cr|-rc)\b|\bspctl\s+--master-disable/i],
  ['osascript', 'careful', 'Runs AppleScript, which can show fake password prompts or control other apps.', /\bosascript\s+-e\b/i],
  ['persistence', 'careful', 'Installs something that starts automatically (LaunchAgent, cron, login item, Run key).', /LaunchAgents|LaunchDaemons|\blaunchctl\s+(?:load|bootstrap)|\bcrontab\b|\/etc\/cron|\.bash_profile|\.zshrc|\.bashrc|\\CurrentVersion\\Run|schtasks\s+\/create|login\s+item/i],
  ['download_chmod_run', 'careful', 'Downloads a file, makes it executable and runs it.', /(?:curl|wget)\b[^\n]*(?:-o|-O|--output)\s*\S+[^\n]*(?:&&|;)\s*chmod\s+\+?[0-7x+]+[^\n]*(?:&&|;)\s*(?:\.\/|\/tmp\/|\$TMPDIR|~\/)/i],
  ['history_wipe', 'careful', 'Clears shell history, which hides what was run.', /\bhistory\s+-c\b|\bunset\s+HISTFILE\b|>\s*~\/\.(?:bash|zsh)_history/i],
  ['sudo_remote', 'careful', 'Runs a downloaded script as administrator (sudo).', /(?:curl|wget)\b[^\n]*\|\s*sudo\b/i],
  ['disable_security', 'careful', 'Turns off a security control (firewall, SIP, Defender, Gatekeeper).', /csrutil\s+disable|Set-MpPreference\s+-Disable|spctl\s+--master-disable|ufw\s+disable|setenforce\s+0|socketfilterfw\s+--setglobalstate\s+off/i],
];

function hostsIn(cmd) {
  const out = [];
  for (const m of String(cmd).matchAll(URL_RE)) {
    try { const u = new URL(m[0]); out.push({ url: m[0], host: u.hostname.toLowerCase(), path: u.pathname }); } catch { /* skip */ }
  }
  return out;
}

function isKnownInstaller({ host, path }) {
  const reg = getRegistrableDomain(host);
  if (host === 'raw.githubusercontent.com') return TRUSTED_RAW_ORGS.has((path.split('/')[1] || '').toLowerCase());
  return KNOWN_INSTALLERS.has(host) || KNOWN_INSTALLERS.has(reg);
}

/** Decode base64 blobs in the command so the hidden payload is checked too. */
function decodedPayloads(cmd) {
  const out = [];
  for (const m of String(cmd).matchAll(/[A-Za-z0-9+/]{40,}={0,2}/g)) {
    try {
      const raw = Buffer.from(m[0], 'base64');
      // PowerShell -EncodedCommand is UTF-16LE.
      const utf16 = raw.toString('utf16le');
      const utf8 = raw.toString('utf8');
      const pick = /^[\x09\x0a\x0d\x20-\x7e]{12,}$/.test(utf16.slice(0, 60)) ? utf16 : utf8;
      if (/^[\x09\x0a\x0d\x20-\x7e]{12,}/.test(pick)) out.push(pick);
    } catch { /* not base64 */ }
  }
  return out;
}

export function checkCommand(command, { context = '' } = {}, depth = 0) {
  const cmd = String(command || '');
  const reasons = [];
  let level = 'safe';
  const add = (id, lvl, message, extra = {}) => { reasons.push({ id, level: lvl, message, ...extra }); level = worst(level, lvl); };

  const shape = CLIP.classifyPayload(cmd);
  if (context) {
    const cf = CLIP.assessClipboardExec({ payload: shape, pageText: context });
    if (cf.fire) add('clickfix', cf.severity === 'high' ? 'stop' : 'careful', cf.severity === 'high'
      ? 'ClickFix: a fake "verify you are human" page wants this command pasted into a terminal or the Run box. No real CAPTCHA ever asks that.'
      : 'The text that came with this command tells a person to paste and run it.');
  }
  for (const [id, lvl, message, re] of RULES) if (re.test(cmd)) add(id, lvl, message);

  // Download-and-run: score each host the command fetches from.
  const hosts = hostsIn(cmd);
  const pipesToShell = shape.exec && (shape.kind === 'shell-pipe' || shape.kind === 'powershell' || shape.kind === 'run-dialog' || shape.kind === 'encoded');
  for (const h of hosts) {
    const known = isKnownInstaller(h);
    const heur = urlHeuristics(h.url);
    const v = heur.safe === true ? 'safe' : verdictFromScore(heur.score || 0, { phishingMode: true });
    if (IP_HOST.test(h.host)) add('raw_ip_host', pipesToShell ? 'stop' : 'careful', `Fetches from a bare IP address (${h.host}) instead of a named site.`);
    else if (v !== 'safe' && !known) add('risky_host', pipesToShell ? 'stop' : 'careful', `Fetches from ${h.host}, which fails SYBA's link checks: ${(heur.findings || []).map((f) => f.message).join(' ')}`.trim());
    if (pipesToShell && !known && !IP_HOST.test(h.host) && v === 'safe') add('unknown_installer', 'careful', `Runs a script straight from ${h.host} without showing it first. ${h.host} is not a known installer host.`);
    if (pipesToShell && known) reasons.push({ id: 'known_installer', level: 'safe', message: `Runs the official install script from ${h.host}.` });
    if (/^http:/i.test(h.url) && pipesToShell) add('plain_http_exec', 'stop', `Runs code fetched over plain HTTP from ${h.host}; anyone on the network can swap it.`);
  }
  if (shape.exec && !hosts.length && shape.kind && shape.kind !== 'clipboard-marker' && !reasons.length) {
    add('exec_shape', 'careful', `Command has an execution shape (${shape.kind}) that is common in paste-to-run attacks.`);
  }
  if (depth === 0) {
    for (const p of decodedPayloads(cmd)) {
      const inner = checkCommand(p, {}, 1);
      add('encoded_payload', worst('careful', inner.level), `Contains an encoded payload that decodes to: ${p.slice(0, 120).replace(/\s+/g, ' ')}`);
      for (const r of inner.reasons) add(`decoded_${r.id}`, r.level, `(inside the decoded payload) ${r.message}`);
    }
  }
  return { verdict: LABEL[level], level, shape: shape.kind, reasons };
}

const NEXT = {
  stop: 'Do not run it. Do not paste it into Terminal, PowerShell or the Run box. Tell the user what it would do; if it came from a "verify you are human" page, close that page.',
  careful: 'Do not run it on autopilot. Show the user what it does and get an explicit yes, or download the script and read it first.',
  safe: 'No paste-to-run danger signs found. Run it only if it does what the user asked for.',
};

async function main(argv) {
  const json = argv.includes('--json');
  const ci = argv.indexOf('--context');
  const context = ci !== -1 ? await readInput(argv[ci + 1]) : '';
  const pos = argv.filter((a, i) => !a.startsWith('--') && (ci === -1 || i !== ci + 1));
  const cmd = pos.length > 1 ? pos.join(' ') : await readInput(pos[0] ?? '-');
  if (!String(cmd).trim()) {
    process.stderr.write('usage: command-check.mjs "<command>" | - [--context <file|text>] [--json]\n');
    process.exit(2);
  }
  const r = checkCommand(cmd, { context });
  if (json) process.stdout.write(JSON.stringify({ ...r, next: NEXT[r.level] }, null, 2) + '\n');
  else {
    const lines = [`${r.verdict}: ${String(cmd).trim().slice(0, 160)}`];
    for (const x of r.reasons) lines.push(`  - [${LABEL[x.level]}] ${x.message}`);
    lines.push(`Next step: ${NEXT[r.level]}`);
    process.stdout.write(lines.join('\n') + '\n');
  }
  process.exit(exitCodeFor(r.level));
}

if (process.argv[1]?.endsWith('command-check.mjs')) main(process.argv.slice(2));

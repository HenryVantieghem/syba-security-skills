#!/usr/bin/env node
// SYBA dependency trust: is this package name a typosquat or lookalike of a popular
// npm or PyPI package? Run it before an agent installs anything.
//
//   node package-check.mjs <name> [more...] [--pypi|--npm] [--online] [--json]
//   node package-check.mjs --command "npm install lodahs axios@1.7"   (also pip/uv/poetry/yarn/pnpm/bun)
//   node package-check.mjs --file package.json | requirements.txt
//
// Offline by default: compares names against SYBA's curated popular-package lists using
// the same lookalike rules SYBA Shield uses for brand domains (doubled-letter omission,
// repetition, transposition, confusable characters). --online also asks the registry
// whether the package exists, how old it is and (npm) how many weekly downloads it has.
//
// Exit code: 0 Safe, 10 Be careful, 20 Stop.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { typosquatKind, foldMultigraphs } from './engine/heuristics.js';
import { worst, exitCodeFor, LABEL } from './engine/verdict.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const load = (f) => fs.readFileSync(path.join(here, 'data', f), 'utf8').split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
const POPULAR = { npm: load('popular-npm.txt'), pypi: load('popular-pypi.txt') };

export const normalizeName = (name, eco) => (eco === 'pypi' ? String(name).toLowerCase().replace(/[-_.]+/g, '-') : String(name).toLowerCase());
const POP_SET = { npm: new Set(POPULAR.npm.map((n) => normalizeName(n, 'npm'))), pypi: new Set(POPULAR.pypi.map((n) => normalizeName(n, 'pypi'))) };

const AFFIXES = ['js', '-js', '.js', '-node', '-cli', '-dev', '-lib', '-sdk', '-api', '-utils', '-util', '-tool', '-tools', '2', '3', '-official', '-secure', '-fix', '-patch', '-latest', '-new', '-core-js', 'py', '-py', '-python', '-lite'];
const PREFIXES = ['node-', 'js-', 'py', 'py-', 'python-', 'python3-', 'official-', 'secure-', 'the-', 'real-'];

function editDistance1(a, b) {
  if (Math.abs(a.length - b.length) > 1 || a === b) return false;
  let i = 0, j = 0, edits = 0;
  while (i < a.length && j < b.length) {
    if (a[i] === b[j]) { i++; j++; continue; }
    if (++edits > 1) return false;
    if (a.length > b.length) i++; else if (a.length < b.length) j++; else { i++; j++; }
  }
  return edits + (a.length - i) + (b.length - j) === 1;
}

const bare = (n) => n.replace(/^@[^/]+\//, '');
const flat = (n) => n.replace(/[-_.]/g, '');
// Same homoglyph folding SYBA Shield applies to domains (paypa1 → paypal, rnicrosoft → microsoft).
const deglyph = (s) => foldMultigraphs(s.replace(/[1!|]/g, 'l').replace(/0/g, 'o').replace(/5/g, 's').replace(/3/g, 'e'));

/** Offline name check against the popular list. */
export function checkName(rawName, eco = 'npm') {
  const name = normalizeName(rawName, eco);
  const reasons = [];
  let level = 'safe';
  const add = (lvl, msg, extra = {}) => { level = worst(level, lvl); reasons.push({ level: lvl, message: msg, ...extra }); };

  if (/[^\x21-\x7e]/.test(rawName)) add('stop', 'The name contains non-ASCII or invisible characters, which can make it look like a different package.');
  if (POP_SET[eco].has(name)) return { name: rawName, ecosystem: eco, verdict: LABEL[level], level, popular: true, reasons: reasons.length ? reasons : [{ level: 'safe', message: `${rawName} is a widely used ${eco} package.` }] };

  for (const pop of POPULAR[eco]) {
    const p = normalizeName(pop, eco);
    if (p.length < 4) continue;
    if (name.startsWith('@') && !p.startsWith('@')) {
      if (bare(name) === p) add('careful', `A scoped copy of the popular unscoped package "${pop}". Check that the scope is the real publisher.`, { lookalikeOf: pop, kind: 'scope' });
      continue;
    }
    if (!name.startsWith('@') && p.startsWith('@')) continue;
    const a = name, b = p;
    const kind = typosquatKind(a, b) || (a !== b && deglyph(a) === deglyph(b) ? 'homoglyph' : null);
    if (kind) { add('stop', `Looks like a typosquat of "${pop}" (${kind}).`, { lookalikeOf: pop, kind }); continue; }
    if (eco === 'npm' && flat(a) === flat(b)) { add('stop', `Same letters as "${pop}" with different separators.`, { lookalikeOf: pop, kind: 'separator' }); continue; }
    if (b.length >= 5 && editDistance1(a, b)) { add('careful', `One letter away from "${pop}".`, { lookalikeOf: pop, kind: 'edit-distance-1' }); continue; }
    if (b.length >= 4 && (AFFIXES.some((s) => a === b + s) || PREFIXES.some((s) => a === s + b))) {
      add('careful', `Built on the popular name "${pop}" with an extra prefix or suffix, a common trick for fake packages.`, { lookalikeOf: pop, kind: 'affix' });
    }
  }
  if (!reasons.length) reasons.push({ level: 'safe', message: `Not a lookalike of any package on SYBA's popular-${eco} list. That alone does not make it trustworthy.` });
  return { name: rawName, ecosystem: eco, verdict: LABEL[level], level, popular: false, reasons };
}

/** Registry facts (only with --online). */
export async function registryFacts(name, eco) {
  const facts = {};
  try {
    if (eco === 'npm') {
      const r = await fetch(`https://registry.npmjs.org/${name.replace('/', '%2F')}`, { headers: { accept: 'application/vnd.npm.install-v1+json; q=1.0, application/json' } });
      if (r.status === 404) return { exists: false };
      const j = await r.json();
      facts.exists = true;
      facts.created = j.time?.created || null;
      facts.versions = Object.keys(j.versions || {}).length;
      const d = await fetch(`https://api.npmjs.org/downloads/point/last-week/${name}`).then((x) => (x.ok ? x.json() : null)).catch(() => null);
      facts.weeklyDownloads = d?.downloads ?? null;
      facts.hasInstallScripts = Object.values(j.versions || {}).slice(-1).some((v) => v.scripts && (v.scripts.preinstall || v.scripts.install || v.scripts.postinstall));
    } else {
      const r = await fetch(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`);
      if (r.status === 404) return { exists: false };
      const j = await r.json();
      facts.exists = true;
      const uploads = Object.values(j.releases || {}).flat().map((f) => f.upload_time_iso_8601).filter(Boolean).sort();
      facts.created = uploads[0] || null;
      facts.versions = Object.keys(j.releases || {}).length;
    }
  } catch (e) {
    facts.error = `registry lookup failed: ${e.message}`;
  }
  return facts;
}

export function applyFacts(result, facts) {
  if (!facts || facts.error) { if (facts?.error) result.reasons.push({ level: 'safe', message: facts.error }); return result; }
  const add = (lvl, msg) => { result.level = worst(result.level, lvl); result.reasons.push({ level: lvl, message: msg }); };
  if (facts.exists === false) add('stop', `No package called "${result.name}" exists on ${result.ecosystem === 'npm' ? 'npm' : 'PyPI'}. It may be a made-up name; anyone could register it later with malware ("slopsquatting").`);
  else {
    const days = facts.created ? (Date.now() - Date.parse(facts.created)) / 864e5 : null;
    if (days !== null && days < 30) add('careful', `First published ${Math.round(days)} days ago.`);
    if (facts.weeklyDownloads != null && facts.weeklyDownloads < 100 && !result.popular) add('careful', `Only ${facts.weeklyDownloads} downloads last week.`);
    if (facts.hasInstallScripts) result.reasons.push({ level: 'safe', message: 'Latest version runs an install script (preinstall/install/postinstall); read it before installing.' });
  }
  result.registry = facts;
  result.verdict = LABEL[result.level];
  return result;
}

/** Package names (and ecosystem) from an install command line. */
export function parseCommand(cmd) {
  const toks = String(cmd).trim().split(/\s+/);
  const out = [];
  let eco = null, collecting = false;
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (/^(?:npm|pnpm|yarn|bun|npx|bunx)$/.test(t)) { eco = 'npm'; collecting = false; continue; }
    if (/^(?:pip3?|uv|poetry|pipx|python3?)$/.test(t)) { eco = 'pypi'; collecting = false; continue; }
    if (/^(?:install|i|add|isntall)$/.test(t) && eco) { collecting = true; continue; }
    if (t === '-m' || t === 'pip') continue;
    if (!collecting || t.startsWith('-') || /[/\\]|^\.|\.(?:txt|toml|json)$/.test(t) && !t.startsWith('@')) continue;
    out.push({ name: stripVersion(t, eco), eco: eco || 'npm' });
  }
  return out;
}

function stripVersion(spec, eco) {
  if (eco === 'pypi') return spec.replace(/\[.*?\]/, '').split(/[=<>!~;@ ]/)[0];
  const at = spec.lastIndexOf('@');
  return at > 0 ? spec.slice(0, at) : spec;
}

export function parseFile(file) {
  const text = fs.readFileSync(file, 'utf8');
  if (/package\.json$/.test(file)) {
    const j = JSON.parse(text);
    return Object.keys({ ...j.dependencies, ...j.devDependencies, ...j.optionalDependencies, ...j.peerDependencies }).map((name) => ({ name, eco: 'npm' }));
  }
  return text.split('\n').map((l) => l.replace(/#.*/, '').trim()).filter((l) => l && !l.startsWith('-')).map((l) => ({ name: stripVersion(l, 'pypi'), eco: 'pypi' }));
}

async function main(argv) {
  const json = argv.includes('--json');
  const online = argv.includes('--online');
  const defEco = argv.includes('--pypi') ? 'pypi' : 'npm';
  const vi = (f) => { const i = argv.indexOf(f); return i === -1 ? undefined : argv[i + 1]; };
  let items;
  if (vi('--command')) items = parseCommand(vi('--command'));
  else if (vi('--file')) items = parseFile(vi('--file'));
  else items = argv.filter((a, i) => !a.startsWith('--') && !['--command', '--file'].includes(argv[i - 1])).map((name) => ({ name, eco: defEco }));
  if (!items.length) {
    process.stderr.write('usage: package-check.mjs <name...> [--pypi] [--online] [--json] | --command "<install cmd>" | --file <package.json|requirements.txt>\n');
    process.exit(2);
  }
  const results = [];
  for (const it of items) {
    let r = checkName(it.name, it.eco);
    if (online) r = applyFacts(r, await registryFacts(it.name, it.eco));
    results.push(r);
  }
  const overall = worst(...results.map((r) => r.level));
  if (json) process.stdout.write(JSON.stringify({ verdict: LABEL[overall], results }, null, 2) + '\n');
  else {
    for (const r of results) {
      process.stdout.write([`${r.verdict}: ${r.name} (${r.ecosystem})`, ...r.reasons.map((x) => `  - ${x.message}`)].join('\n') + '\n');
    }
    const next = { stop: 'Do not install it. Use the real package name, or ask the user which package they meant.', careful: 'Do not install on autopilot. Confirm the exact name with the user or the project\'s official docs first.', safe: 'No lookalike found. Install only what the task needs, and pin the version.' };
    process.stdout.write(`Next step: ${next[overall]}\n`);
  }
  process.exit(exitCodeFor(overall));
}

if (process.argv[1]?.endsWith('package-check.mjs')) main(process.argv.slice(2));

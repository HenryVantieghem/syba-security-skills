#!/usr/bin/env node
// Copy the shared SYBA detectors from engine/ into each skill's scripts/engine/,
// so every skill folder works on its own when copied into ~/.claude/skills or
// ~/.agents/skills. Run after editing anything in engine/.
//
//   node scripts/sync-engine.mjs           copy
//   node scripts/sync-engine.mjs --check   exit 1 if any skill copy differs from engine/

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const URL_ENGINE = ['heuristics.js', 'idn.js', 'safe-domains.js'];
export const MAP = {
  'syba-link-check': [...URL_ENGINE, 'verdict.js'],
  'syba-email-check': [...URL_ENGINE, 'email-signals.js', 'eml.js', 'verdict.js'],
  'syba-prompt-injection-guard': ['injection-signals.js', 'eml.js', 'verdict.js'],
  'syba-paste-to-run-guard': [...URL_ENGINE, 'clipboard-exec-signals.js', 'verdict.js'],
  'syba-secret-hygiene': ['ask-redact.js', 'verdict.js'],
  'syba-dependency-trust': [...URL_ENGINE, 'verdict.js'],
  'syba-security-review': ['verdict.js'],
};

const check = process.argv.includes('--check');
let drift = 0;
for (const [skill, files] of Object.entries(MAP)) {
  const dest = path.join(root, 'skills', skill, 'scripts', 'engine');
  fs.mkdirSync(dest, { recursive: true });
  const want = new Set([...files, 'package.json']);
  for (const f of files) {
    const src = fs.readFileSync(path.join(root, 'engine', f));
    const to = path.join(dest, f);
    if (check) { if (!fs.existsSync(to) || !fs.readFileSync(to).equals(src)) { console.error(`drift: ${skill}/scripts/engine/${f}`); drift++; } }
    else fs.writeFileSync(to, src);
  }
  if (!check) fs.writeFileSync(path.join(dest, 'package.json'), '{"type":"module"}\n');
  for (const f of fs.readdirSync(dest)) if (!want.has(f)) { if (check) { console.error(`extra: ${skill}/scripts/engine/${f}`); drift++; } else fs.rmSync(path.join(dest, f)); }
}
if (check && drift) process.exit(1);
console.log(check ? 'engine copies match' : 'engine synced into every skill');

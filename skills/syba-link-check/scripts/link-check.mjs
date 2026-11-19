#!/usr/bin/env node
// SYBA link check: is this URL a phishing page, a brand lookalike or an IDN homograph?
// Runs the SYBA Shield extension's own URL detectors, offline.
//
//   node link-check.mjs <url-or-domain> [more...] [--json] [--strict]
//   node link-check.mjs --text <file|->            # every link found in a block of text
//
// Exit code: 0 Safe, 10 Be careful, 20 Stop (worst across all inputs).

import { urlHeuristics, verdictFromScore } from './engine/heuristics.js';
import { decodeIdnHostname } from './engine/idn.js';
import { levelOf, worst, exitCodeFor, readInput, LABEL } from './engine/verdict.js';

const URL_IN_TEXT = /\b(?:https?:\/\/|www\.)[^\s<>"'`)\]]+/gi;

export function normalize(input) {
  let s = String(input || '').trim().replace(/^<|>$/g, '').replace(/[.,;:!?]+$/, '');
  if (!s) return '';
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = `https://${s}`;
  return s;
}

const NEXT = {
  stop: "Don't open it, and don't enter a password, code or card number there. Go to the company's site by typing its address yourself.",
  careful: 'Only continue if you expected this link. Check the address letter by letter, or reach the site from a bookmark instead.',
  safe: 'No warning signs found offline. This is not a guarantee: a brand-new phishing page can look clean.',
};

/** One URL in, one verdict out. `strict` uses the extension's Phishing Detector thresholds. */
export function checkUrl(input, { strict = false } = {}) {
  const url = normalize(input);
  const h = urlHeuristics(url);
  const verdict = h.safe === true ? 'safe' : verdictFromScore(h.score || 0, { phishingMode: strict });
  const level = levelOf(verdict);
  const host = h.host || '';
  const shown = host.includes('xn--') ? decodeIdnHostname(host) : host;
  return {
    input,
    url,
    host,
    displayHost: shown,
    verdict: LABEL[level],
    level,
    score: h.score || 0,
    knownSafeDomain: h.safe === true,
    reasons: (h.findings || []).map((f) => ({ id: f.id, severity: f.severity, message: f.message })),
    next: NEXT[level],
  };
}

export function linksInText(text) {
  return [...new Set((String(text || '').match(URL_IN_TEXT) || []).map(normalize))];
}

async function main(argv) {
  const json = argv.includes('--json');
  const strict = argv.includes('--strict');
  const rest = argv.filter((a) => !a.startsWith('--'));
  let inputs = rest;
  const ti = argv.indexOf('--text');
  if (ti !== -1) inputs = linksInText(await readInput(argv[ti + 1] && !argv[ti + 1].startsWith('--') ? argv[ti + 1] : '-'));
  else if (!inputs.length) inputs = (await readInput('-')).split(/\s+/).filter(Boolean);
  if (!inputs.length) {
    process.stderr.write('usage: link-check.mjs <url-or-domain> [...] [--json] [--strict] | --text <file|->\n');
    process.exit(2);
  }
  const results = inputs.map((u) => checkUrl(u, { strict }));
  const overall = worst(...results.map((r) => r.level));
  if (json) process.stdout.write(JSON.stringify({ verdict: LABEL[overall], results }, null, 2) + '\n');
  else {
    for (const r of results) {
      const idn = r.displayHost && r.displayHost !== r.host ? ` (shown as ${r.displayHost})` : '';
      const lines = [`${r.verdict}: ${r.url}${idn}`];
      if (r.knownSafeDomain) lines.push('  - On SYBA\'s list of known genuine domains.');
      for (const f of r.reasons) lines.push(`  - [${f.severity}] ${f.message}`);
      lines.push(`Next step: ${r.next}`);
      process.stdout.write(lines.join('\n') + '\n\n');
    }
  }
  process.exit(exitCodeFor(overall));
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('link-check.mjs')) main(process.argv.slice(2));

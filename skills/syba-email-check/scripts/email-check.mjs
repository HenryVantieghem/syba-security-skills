#!/usr/bin/env node
// SYBA email check: is this email phishing?
// Runs the SYBA Shield extension's email detectors (sender spoof, deceptive links,
// malicious links, stacked urgency) plus a credential-request check, offline.
//
//   node email-check.mjs message.eml [--json]
//   node email-check.mjs - [--from "PayPal <x@y.com>"] < pasted.txt
//
// Exit code: 0 Safe, 10 Be careful, 20 Stop.

import { urlHeuristics, verdictFromScore } from './engine/heuristics.js';
import { isSafeDomain } from './engine/safe-domains.js';
import './engine/email-signals.js';
import { parseEml, parsePasted, looksLikeEml } from './engine/eml.js';
import { levelOf, exitCodeFor, readInput, LABEL } from './engine/verdict.js';

const S = globalThis.SYBA_EMAIL_SIGNALS;

// Credential traps: the body asks the reader to hand over a secret. Corroboration,
// like urgency: it never fires a warning on its own, because real banks and
// services also write "never share your password".
const CREDENTIAL_ASK = /\b(?:enter|confirm|verify|update|provide|re-?enter|submit|validate)\s+(?:your\s+)?(?:password|passcode|login(?:\s+details)?|credentials|card\s+(?:number|details)|billing\s+(?:info|information|details)|social\s+security|ssn|pin|one[-\s]?time\s+code|verification\s+code|seed\s+phrase|recovery\s+phrase|bank\s+details)\b/i;
const NEGATED = /\b(?:never|will not|won't|do not|don't)\b[^.]{0,40}\b(?:ask|share|enter|send)\b/i;

const NEXT = {
  stop: "Don't click any link, open any attachment or reply. If you think it might be real, sign in by typing the company's address yourself, then delete or report the email.",
  careful: 'Check the sender address and hover each link before you trust it. Reach the company through its own site or app, not through this email.',
  safe: 'No phishing signs found. Still never send a password or code by email.',
};

function scoreUrl(u) {
  try {
    const host = new URL(u).hostname.toLowerCase();
    if (isSafeDomain(host)) return 'safe';
    return verdictFromScore(urlHeuristics(u).score, { phishingMode: true });
  } catch { return null; }
}

/** The extension's email scan, with the service worker's link scoring done inline. */
export function assessEmail(email) {
  const links = (email.links || []).filter((l) => /^https?:/i.test(l.href || ''));
  const uniqueLinks = [...new Set(links.map((l) => l.href))].slice(0, 25);
  const senderDomain = email.from?.email ? email.from.email.split('@')[1] || '' : '';
  const risk = new Map();
  for (const u of uniqueLinks) risk.set(u, scoreUrl(u));
  const senderDomainRisk = senderDomain ? scoreUrl(`https://${senderDomain}/`) : null;
  const hostOf = (u) => { try { return new URL(u).hostname.toLowerCase(); } catch { return ''; } };

  const findings = [];
  for (const a of links) {
    const f = S.linkTextMismatch({ text: a.text || '', host: hostOf(a.href), href: a.href }, { linkRisk: risk.get(a.href) || null });
    if (f) { findings.push(f); break; }
  }
  const spoof = email.from ? S.senderSpoof({ name: email.from.name || '', email: email.from.email || '' }, { senderDomainRisk }) : null;
  if (spoof) findings.push(spoof);
  for (const u of uniqueLinks) {
    const v = risk.get(u);
    if (v !== 'phishing' && v !== 'suspicious') continue;
    findings.push({ id: 'malicious_link', severity: v === 'phishing' ? 'high' : 'medium', message: `A link points to ${hostOf(u)}, which fails SYBA's link checks.`, url: u });
    break;
  }
  if (email.replyTo?.email && senderDomain) {
    const rd = email.replyTo.email.split('@')[1] || '';
    if (rd && S.registrableDomain(rd) !== S.registrableDomain(senderDomain) && S.claimsBrand(email.from?.name || '').length) {
      findings.push({ id: 'reply_to_mismatch', severity: 'medium', message: `Replies go to ${rd}, not to the sender's domain ${senderDomain}.` });
    }
  }
  const urgency = S.urgencySignal(`${email.subject || ''}\n${email.text || ''}`);
  if (urgency) findings.push(urgency);
  const body = email.text || '';
  if (CREDENTIAL_ASK.test(body) && !NEGATED.test(body.match(new RegExp(`[^.]*${CREDENTIAL_ASK.source}[^.]*`, 'i'))?.[0] || '')) {
    findings.push({ id: 'credential_request', severity: 'low', message: 'The email asks you to enter or confirm a password, code or payment details.' });
  }
  const a = S.assessEmail(findings);
  const level = levelOf(a.level);
  return {
    verdict: LABEL[level],
    level,
    score: a.score,
    from: email.from,
    subject: email.subject,
    senderDomainRisk,
    linksChecked: uniqueLinks.length,
    reasons: a.findings.map((f) => ({ id: f.id, severity: f.severity, message: f.message })),
    // Signals seen but too weak alone to earn a warning (kept for the explanation).
    weakSignals: a.findings.length ? [] : findings.map((f) => f.message),
    next: NEXT[level],
  };
}

export function assessRaw(raw, from) {
  return assessEmail(looksLikeEml(raw) ? parseEml(raw) : parsePasted(raw, from));
}

async function main(argv) {
  const json = argv.includes('--json');
  const fi = argv.indexOf('--from');
  const from = fi !== -1 ? argv[fi + 1] : undefined;
  const pos = argv.filter((a, i) => !a.startsWith('--') && (fi === -1 || i !== fi + 1));
  const raw = await readInput(pos[0] ?? '-');
  if (!raw.trim()) {
    process.stderr.write('usage: email-check.mjs <message.eml | - > [--from "Name <addr>"] [--json]\n');
    process.exit(2);
  }
  const r = assessRaw(raw, from);
  if (json) process.stdout.write(JSON.stringify(r, null, 2) + '\n');
  else {
    const who = r.from ? `${r.from.name ? `"${r.from.name}" ` : ''}<${r.from.email}>` : 'unknown sender';
    const lines = [`${r.verdict}: email from ${who}${r.subject ? `, subject "${r.subject}"` : ''}`];
    for (const f of r.reasons) lines.push(`  - [${f.severity}] ${f.message}`);
    for (const w of r.weakSignals) lines.push(`  - (weak, not enough alone) ${w}`);
    lines.push(`  (${r.linksChecked} link${r.linksChecked === 1 ? '' : 's'} checked)`);
    lines.push(`Next step: ${r.next}`);
    process.stdout.write(lines.join('\n') + '\n');
  }
  process.exit(exitCodeFor(r.level));
}

if (process.argv[1]?.endsWith('email-check.mjs')) main(process.argv.slice(2));

// SYBA Shield — phishing heuristics (URL + DOM signals).
// Pure functions, no chrome.* or DOM access. Safe in any context.

import { isSafeDomain } from './safe-domains.js';
import { decodeIdnHostname, hasMixedScriptLabel, foldConfusables } from './idn.js';

// v1.3.1 — trimmed to genuinely-abused TLDs. Removed legit-friendly TLDs that
// many real businesses now use (.work .support .link .fit .rest .lol .review)
// to stop false positives. The remainder still skew heavily toward phishing
// kits per APWG / Spamhaus 2024-2025.
export const SUSPICIOUS_TLDS = new Set([
  'zip', 'mov', 'country', 'kim', 'cricket', 'science', 'review',
  'party', 'gq', 'top', 'click', 'cf', 'tk', 'ml', 'ga',
  'xin', 'racing', 'win', 'download', 'stream', 'bid', 'loan',
  // v1.13.0 — newer gTLDs consistently topping the Interisle / Spamhaus 2024-2025
  // abuse tables with little legitimate business use. Kept OFF anything with real
  // commercial adoption (.xyz, .online, .site, .club, .icu) to protect the 0% FP
  // gate. All validated to add 0 false positives across the fp-gate corpus.
  'cyou', 'sbs', 'cfd', 'bond', 'quest', 'lat', 'mom',
]);

// Free-TLD farms with >90% abuse rates per Spamhaus / APWG 2024-2025. Triggers
// high severity because the TLD itself is a phishing signal regardless of name.
// .top removed (high volume but well under the >90% bar and used by legit sites).
export const HIGH_ABUSE_TLDS = new Set([
  'zip', 'mov', 'gq', 'tk', 'ml', 'ga', 'cf', 'kim',
  // v1.13.0 — sustained >90% malicious-registration rates in Interisle's 2024 &
  // 2025 "Phishing Landscape" and Spamhaus TLD reputation; effectively no legit
  // business footprint.
  'cyou', 'sbs', 'cfd',
]);

export const HIGH_VALUE_BRANDS = [
  'paypal', 'apple', 'icloud', 'google', 'microsoft', 'office365',
  'amazon', 'netflix', 'facebook', 'instagram', 'whatsapp',
  // v1.12.0 — `bankofamerica` added: the list carried only the abbreviation `bofa`,
  // so `bankofamerica.secure-verify-login.xyz` (a textbook fake-bank subdomain, and a
  // case in eval/cases.json) verdicted SAFE. This is a data gap, NOT a loosened
  // matcher: the brand must still appear as a whole label token, and the real
  // bankofamerica.com is protected by both the safe-domain allowlist and the
  // `regStem === brand` skip. Verified to add 0 false positives across the 401-host gate.
  'chase', 'bofa', 'bankofamerica', 'wellsfargo', 'citi', 'hsbc', 'barclays',
  'kbc', 'ing', 'belfius', 'argenta', 'fortis', 'bnpparibas',
  'syba', 'sybainsurance', 'personalguard', 'agentshield',
  'fsma', 'nbb', 'belgium',
  'binance', 'coinbase', 'kraken', 'metamask', 'trezor', 'ledger',
  'docusign', 'dropbox', 'github', 'linkedin', 'slack',
  // v1.13.0 — expanded curated set of the most-impersonated brands (APWG /
  // Interisle 2024-2025). DELIBERATELY only DISTINCTIVE, non-dictionary-word
  // names: a brand token is matched as a whole label boundary against EVERY
  // label of a host, so a common English/Dutch/French word (booking, steam,
  // target, wise, outlook) would false-flag a legitimate subdomain that uses it
  // (e.g. booking.marriott.com) — a class the 401-host gate cannot see. Every
  // addition below is a coined name with negligible standalone-word usage, and
  // each is validated to add 0 false positives across the fp-gate corpus.
  // Webmail / productivity
  'hotmail', 'protonmail', 'mailchimp',
  // Fintech + payments
  'revolut', 'robinhood', 'venmo', 'zelle', 'wetransfer',
  // Crypto exchanges / wallets
  'bybit', 'bitfinex', 'bitstamp', 'blockfi', 'uphold',
  // Parcels / logistics (heavy smishing → phishing pivots)
  'fedex', 'usps', 'dpdgroup', 'bpost',
  // Telecom / ISP
  'verizon', 'xfinity', 'proximus', 'telenet',
  // Retail
  'walmart', 'costco', 'coolblue',
  // Social / comms
  'telegram', 'tiktok', 'snapchat', 'pinterest', 'roblox',
  // Streaming / creative
  'spotify', 'adobe', 'disney',
  // EU / Benelux banks + insurers (SYBA's core market)
  'santander', 'natwest', 'lloyds', 'rabobank', 'abnamro', 'commerzbank',
  'unicredit', 'sabadell', 'monzo', 'deutschebank', 'ethias', 'axabank',
];

// v1.12.0 — the common two-label public suffixes. A full Public Suffix List is too
// heavy to bundle in an MV3 service worker, but the old "always take the last 2
// labels" rule computed getRegistrableDomain('paypal.co.uk') === 'co.uk', so the
// registrable STEM read as 'co' instead of 'paypal'. That silently defeated the
// "this is the legit brand" check for every brand on a two-part ccTLD. Covering the
// common suffixes is what makes the subdomain-impersonation catch below safe.
const TWO_PART_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'me.uk', 'net.uk', 'sch.uk', 'nhs.uk',
  'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
  'co.nz', 'net.nz', 'org.nz',
  'co.za', 'org.za',
  'com.br', 'net.br', 'org.br', 'gov.br',
  'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp',
  'com.cn', 'net.cn', 'org.cn', 'gov.cn',
  'co.in', 'net.in', 'org.in',
  'co.kr', 'or.kr',
  'co.il', 'org.il',
  'com.mx', 'com.ar', 'com.tr', 'com.sg', 'com.hk', 'com.tw', 'com.my',
  'com.ph', 'com.vn', 'com.pl', 'com.ua', 'com.ru', 'com.es', 'com.pt',
]);

export function getRegistrableDomain(hostname) {
  if (!hostname) return '';
  const lower = hostname.toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
  const parts = lower.split('.');
  if (parts.length <= 2) return lower;
  if (TWO_PART_SUFFIXES.has(parts.slice(-2).join('.'))) return parts.slice(-3).join('.');
  return parts.slice(-2).join('.');
}

export function getTld(hostname) {
  const parts = (hostname || '').split('.');
  return (parts[parts.length - 1] || '').toLowerCase();
}

// v1.12.0 — `levenshtein()` was REMOVED along with the blanket "distance <= 2"
// lookalike rule it powered. Edit distance is the wrong tool for brand spoofing: it
// cannot tell `gogle`←google (a typosquat) from `apply`←apple (an unrelated word),
// because both are one edit away. Reach for `typosquatKind()` below instead — it
// classifies the OPERATION. If you find yourself re-adding a distance function to
// catch one more phishing sample, re-read the false-positive history in
// references/dev-loop.md first: this exact class has already regressed once.

export function hasIdnHomograph(hostname) {
  if (!hostname) return false;
  // v1.3.2 — a clean single-script internationalized domain (müller.de, café.fr,
  // 日本.jp) is legitimate, not an attack. `URL.hostname` hands us the punycode
  // form, so the old "any xn-- is a homograph" rule false-flagged every IDN.
  // Decode, then flag only genuine homoglyph signals: a label that mixes scripts
  // (pаypal — Latin+Cyrillic), or punycode that won't decode at all.
  const unicode = decodeIdnHostname(hostname);
  if (/(^|\.)xn--/i.test(unicode)) return true;       // undecodable punycode → risky
  if (!/[^\x00-\x7F]/.test(unicode)) return false;    // pure ASCII → no IDN at all
  return hasMixedScriptLabel(unicode);
}

// Normalize common homoglyph swaps (1↔l, 0↔o, 5↔s, etc.) so paypa1 → paypal.
function deglyph(s) {
  return s
    .replace(/[1!|]/g, 'l')
    .replace(/0/g, 'o')
    .replace(/5\$/g, 's')
    .replace(/@/g, 'a')
    .replace(/3/g, 'e')
    .toLowerCase();
}

// v1.12.0 — MULTIGRAPH confusables: letter PAIRS that render as a single letter at
// a glance. 'rn' is the classic ("rnicrosoft.com" reads as "microsoft.com" in a URL
// bar). Single-char homoglyphs are handled by deglyph() above; these need their own
// pass because they change the string's length.
export function foldMultigraphs(s) {
  return String(s || '')
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/cl/g, 'd');
}

// v1.12.0 — single-character substitutions that are VISUALLY confusable. Kept
// deliberately tiny. Every pair here must be defensible as "a human skimming a URL
// bar could miss this"; an arbitrary letter swap is NOT confusable and must never be
// added (that is precisely the false-positive class this release fixes).
const CONFUSABLE_SUBS = [
  ['m', 'n'],   // amazom ← amazon
  ['u', 'v'],   // paypaI-style stroke confusion
  ['i', 'j'],
  ['q', 'g'],
];

function isConfusablePair(a, b) {
  return CONFUSABLE_SUBS.some(([x, y]) => (a === x && b === y) || (a === y && b === x));
}

/**
 * v1.12.0 — TYPOSQUAT CLASSIFIER. Replaces the blanket "Levenshtein <= 2" lookalike
 * rule, which was a major false-positive source: it flagged ANY label within two
 * arbitrary edits of a brand, so real sites read as impersonation —
 *   apply → apple (e↔y), black → slack (s↔b), phase → chase (c↔p),
 *   amazing → amazon, maple → apple
 * all verdicted `suspicious` (measured 2026-07-15: 5.4% of legitimate sites).
 *
 * The insight: every false positive was an ARBITRARY substitution, and every true
 * positive was one of a small set of well-known typosquat OPERATIONS. So classify
 * the operation instead of measuring distance. This is the standard typosquatting
 * taxonomy (omission / repetition / transposition / confusable substitution) used by
 * dnstwist and URLCrazy — not an ad-hoc carve-out.
 *
 * Returns the operation name, or null when `label` is not a typosquat of `brand`.
 * NOTE: this deliberately does NOT catch arbitrary-substitution squats (paypol ←
 * paypal). That is by design — per references/dev-loop.md, tier-1 under-flagging is
 * expected and the AI tier escalates. Do NOT widen this to chase tier-1 recall; that
 * is exactly how the substring-FP bug came back in 1.11.0.
 *
 * @param {string} label
 * @param {string} brand
 * @returns {'omission'|'repetition'|'transposition'|'confusable-substitution'|null}
 */
export function typosquatKind(label, brand) {
  const a = String(label || '');
  const b = String(brand || '');
  if (!a || !b || a === b) return null;

  // Omission — a DOUBLED letter typed once: gogle ← google ("one o, not two").
  //
  // v1.12.0: restricted to doubled letters after measurement. Unrestricted omission
  // is a false-positive engine, because dropping any one letter from a 6-letter brand
  // lands on the dense space of 5-letter real words — all of these fired:
  //   ledge ← ledger, leger ← ledger (NL/FR word), edger ← ledger,
  //   forts ← fortis, raken ← kraken (Dutch verb), case ← chase
  // None is a plausible typosquat; each is just a word. Requiring the omitted
  // character to be half of a double pair keeps the real error class ("I typed one
  // 'o' in google") and drops the coincidences, because a brand's doubled letter is
  // a specific, rare structure rather than an arbitrary position.
  if (b.length - a.length === 1) {
    for (let i = 0; i < b.length; i++) {
      if (b.slice(0, i) + b.slice(i + 1) !== a) continue;
      if (b[i - 1] === b[i] || b[i + 1] === b[i]) return 'omission';
    }
  }

  // Repetition — one character doubled: paypall ← paypal, gooogle ← google.
  // Restricted to repeats of an ADJACENT character; an arbitrary inserted letter is
  // not a lookalike and would re-open the false-positive class.
  if (a.length - b.length === 1) {
    for (let i = 0; i < a.length; i++) {
      if (a.slice(0, i) + a.slice(i + 1) !== b) continue;
      const c = a[i];
      if (a[i - 1] === c || a[i + 1] === c) return 'repetition';
    }
  }

  if (a.length === b.length) {
    // Transposition — two adjacent characters swapped: googel ← google.
    for (let i = 0; i < b.length - 1; i++) {
      if (b[i] === b[i + 1]) continue;
      const swapped = b.slice(0, i) + b[i + 1] + b[i] + b.slice(i + 2);
      if (swapped === a) return 'transposition';
    }
    // Confusable substitution — exactly one character differs AND that pair is
    // visually confusable. `apply`/`apple` differ by one char too, but e↔y is not
    // confusable, so it correctly does NOT match.
    let diff = -1;
    for (let i = 0; i < b.length; i++) {
      if (a[i] === b[i]) continue;
      if (diff !== -1) { diff = -2; break; }
      diff = i;
    }
    if (diff >= 0 && isConfusablePair(a[diff], b[diff])) return 'confusable-substitution';
  }

  return null;
}

export function looksLikeBrandImpersonation(hostname) {
  // v1.3.1 — never flag brand-owned infra / top-tier domains (googleapis.com,
  // login.microsoftonline.com, raw.githubusercontent.com, media-amazon.com, …).
  if (isSafeDomain(hostname)) return [];
  const reg = getRegistrableDomain(hostname);
  const regStem = reg.split('.')[0] || '';
  const matches = [];
  const seen = new Set();

  // Candidate labels to test against each brand. ASCII labels are tested as-is.
  // For an internationalized host we ALSO test the confusable-folded form of each
  // decoded label (аррӏе → apple, pаypal → paypal) so whole-script homoglyph
  // brand spoofs are caught. Folded candidates are only added when folding
  // actually changes the label, so ordinary IDNs (müller, café) add nothing and
  // pure-ASCII hosts behave exactly as before.
  // v1.11.0 FP fix — exclude the public-suffix / TLD label itself. The final
  // label of a registrable host ('app' in cash.app, 'com', 'io') is NOT a place a
  // brand hides, but it fuzzy-matched brands (Levenshtein 'app'→'apple'=2), so
  // EVERY .app SaaS (linear.app, vercel.app, notion.app) read as impersonation.
  // Real spoofs live in the registrable stem + subdomains, which we keep.
  const dropTld = (labels) => (labels.length > 1 ? labels.slice(0, -1) : labels);
  const candidates = dropTld(hostname.split('.').filter(Boolean))
    .map((l) => ({ text: l, original: l, folded: false }));
  const decoded = decodeIdnHostname(hostname);
  if (decoded !== hostname) {
    for (const d of dropTld(decoded.split('.').filter(Boolean))) {
      const f = foldConfusables(d);
      if (f !== d) candidates.push({ text: f, original: d, folded: true });
    }
  }

  function pushMatch(brand, kind, label, extra = {}) {
    const key = `${brand}|${kind}|${label}`;
    if (seen.has(key)) return;
    seen.add(key);
    matches.push({ brand, kind, stem: label, ...extra });
  }

  for (const brand of HIGH_VALUE_BRANDS) {
    // Exact registrable match — that's the legit brand, not impersonation.
    if (regStem === brand) continue;

    // Short brands (<5 chars like "ing", "kbc") cause substring false positives
    // ('ing' matches 'username'), so they never fuzzy-match at all.
    //
    // v1.12.0 — the fuzzy-match floor is 6, not 5. A typosquat OPERATION on a
    // 5-letter brand yields a 4-letter string, and 4-letter strings are dense in
    // ordinary English: `case.edu` (Case Western Reserve University) is exactly one
    // omission from `chase`, and `aple`/`chse` sit in the same space. At 6+ letters
    // the collision stops being plausible (`gogle`, `paypall`, `amazom` are not
    // words). Brands below the floor keep the checks that need no fuzziness:
    // token-boundary containment (rule 1) and homoglyph/multigraph folding (rule 2) —
    // so `app1e.com`, `paypal-login.gq` and Cyrillic `аррӏе` are all still caught.
    // KNOWN TRADEOFF: a bare omission squat of a 5-letter brand (`aple.com`) is not
    // caught at tier 1. That is the documented design — tier 1 under-flags by intent
    // and the AI tier escalates; per references/dev-loop.md, widening this to chase
    // tier-1 recall is exactly how the false-positive class keeps coming back.
    const tooShortForFuzzy = brand.length < 6;
    // v1.3.1 — token-boundary containment for ALL brands, not just short ones.
    // Plain substring matching flagged legit infra (googleapis, microsoftonline,
    // githubusercontent, paypalobjects). Requiring the brand to sit at a label
    // boundary (separated by - _ . or label edges) still catches real attacks
    // like "paypal-login", "secure-paypal", "account.paypal.evil.gq".
    const boundaryRe = new RegExp(`(^|[-_.])${brand}([-_.]|$)`);

    // Check EVERY label of the hostname (plus folded IDN forms), not just the
    // registrable stem. Catches paypal in subdomain.account.security-update.gq
    // style attacks and IDN homoglyph spoofs.
    for (const cand of candidates) {
      const label = cand.text;
      // v1.12.0 FIXED FALSE NEGATIVE — this used to `continue` whenever a label was
      // exactly the brand, on the theory that "an exact label equal to the brand is
      // the legit brand itself". That is only true when the brand is the REGISTRABLE
      // STEM, which the `regStem === brand` check above already handles (and which
      // now works for two-part ccTLDs too). The blanket skip meant the brand hiding
      // in a SUBDOMAIN of someone else's domain sailed through:
      //   account.paypal.evil.gq  → registrable evil.gq  → was NOT flagged
      //   paypal.com.evil.gq      → registrable evil.gq  → was NOT flagged
      // — both textbook attacks, and the comment on rule 1 below even claimed they
      // were caught. They were not. Reaching here with label === brand now means the
      // brand sits in a subdomain of a domain the brand does not own, so rule 1's
      // boundary match correctly fires.
      if (!label) continue;
      const deg = deglyph(label);

      // 1. Token-boundary containment (paypal as a standalone token in label).
      if (boundaryRe.test(label)) {
        const registrableLabel = cand.original === regStem;
        const abusedTldCorroborates = SUSPICIOUS_TLDS.has(getTld(hostname));
        pushMatch(brand, cand.folded ? 'idn-homoglyph' : 'contains', cand.original,
          (cand.folded || registrableLabel || abusedTldCorroborates) ? {} : { strength: 'corroborating' });
        break;
      }
      // 2. Homoglyph-normalized token-boundary containment (paypa1 → paypal), now
      //    including MULTIGRAPH folding so rnicrosoft → microsoft is caught here as
      //    an exact match rather than relying on a fuzzy distance.
      const multi = foldMultigraphs(deg);
      if (boundaryRe.test(deg) && deg !== label) {
        pushMatch(brand, cand.folded ? 'idn-homoglyph' : 'homoglyph', cand.original, { normalized: deg });
        break;
      }
      if (boundaryRe.test(multi) && multi !== label && multi !== deg) {
        pushMatch(brand, cand.folded ? 'idn-homoglyph' : 'homoglyph', cand.original, { normalized: multi });
        break;
      }
      // 3. Typosquat operations (v1.12.0 — replaces blanket Levenshtein <= 2, which
      //    flagged apply→apple / black→slack / phase→chase / amazing→amazon /
      //    maple→apple: 5.4% of legitimate sites). See typosquatKind() for the full
      //    reasoning. Short brands (<5 chars: kbc, ing, nbb) remain excluded from
      //    fuzzy matching entirely — one edit from a 3-char brand matches a huge set
      //    of unrelated real institutions (rbc=Royal Bank of Canada, bbc=BBC,
      //    who.int vs 'ing'). Folded IDN candidates are skipped for the same reason.
      if (!cand.folded && !tooShortForFuzzy) {
        const kind = typosquatKind(label, brand)
          || (deg !== label ? typosquatKind(deg, brand) : null)
          || (multi !== label && multi !== deg ? typosquatKind(multi, brand) : null);
        if (kind) {
          pushMatch(brand, 'lookalike', cand.original, { op: kind });
          break;
        }
      }
    }
  }
  return matches;
}

// v1.11.0 — random / algorithmically-generated domain detector (Francis bug:
// `site2723vftu6f-it.com` showed "SAFE" because it tripped no rule). Short-lived
// phishing kits overwhelmingly use machine-generated names: letters and digits
// interleaved in 2+ groups (DGA-style). This is the discriminator that separates
// `site2723vftu6f-it` (2 digit groups, high entropy) from long legitimate
// word-domains like `bnpparibasfortis` or `microsoftonline` (ZERO digits) — so it
// is FP-safe against the golden bank/insurer set (none of which contain a digit).
// Conservative by design: MEDIUM severity → 'suspicious'/warn, never a hard block.
export function looksAlgorithmicallyGenerated(label) {
  const raw = String(label || '').toLowerCase();
  const alnum = raw.replace(/[^a-z0-9]/g, '');
  if (alnum.length < 12) return false;                 // short names: too many legit (office365, 7-eleven)
  const digits = (alnum.match(/[0-9]/g) || []).length;
  if (digits < 3) return false;                        // requires real digit content (excludes every word-brand)
  if (digits / alnum.length > 0.7) return false;       // mostly-numeric = an ID/year class, not this pattern
  const letters = alnum.replace(/[0-9]/g, '');
  if (letters.length < 3) return false;
  const digitGroups = (raw.match(/[0-9]+/g) || []).length;
  if (digitGroups < 2) return false;                   // a single trailing/leading run (office365, 123movies) is legit
  const freq = {};
  for (const c of alnum) freq[c] = (freq[c] || 0) + 1;
  let entropy = 0;
  for (const k in freq) { const p = freq[k] / alnum.length; entropy -= p * Math.log2(p); }
  return entropy >= 3.0;
}

// ---------------------------------------------------------------------------
// PLAN-90 A3/A4 — shared-hosting tenant labels and credential-bearing URLs.
//
// WHAT THE MEASUREMENT SAID (2026-09-15, 112 live hosts from the event-time
// PhishTank poller). The URL layer caught 32. Of the 48 it missed with no
// domain-age signal either, most were not obscure: they were a free tenant on
// somebody else's hosting, with the lure written into the tenant name.
//   security-server-landing-page--ikramkhan83.replit.app
//   office-365-msn--oficeer.replit.app
//   mail-login-pt.weebly.com · connectxfinitysignin.weeblysite.com
//   account-att-com-a96077.webflow.io · sapo-mail-19350.bubbleapps.io
//   666234567263456527637853667772356.blogspot.com  (five of this shape)
//   retunanet.z27.web.core.windows.net              (seven of this shape)
// On a shared-hosting suffix the tenant label is chosen by whoever signed up and
// costs nothing, so it carries no reputation: "login" in front of weebly.com is
// evidence in a way "login" in front of a company's own domain is not. On an
// ordinary domain these rules DO NOT run, which is what keeps them off
// login.mycompany.com.
//
// Each finding is `medium`, which reaches `suspicious` (a warning) on its own
// and never `phishing`. The FP cost is measured on the platform stratum of
// eval/fp-corpus.json (130 real tenants: adobe.github.io, commerce.vercel.app,
// docs.pages.dev, client-first.webflow.io, gmailblog.blogspot.com …), which is
// why the lure list below holds only credential words and no product words
// (support, mail, update, billing, access all appear in honest tenant names).

/** Hosting where the label(s) to the left are free, self-chosen and disposable. */
export const SHARED_HOSTING_SUFFIXES = [
  'web.core.windows.net', 'blob.core.windows.net', 'azurewebsites.net', 'azurestaticapps.net',
  'storage.googleapis.com', 'firebasestorage.googleapis.com', 'firebaseapp.com', 'web.app',
  'amazonaws.com', 'replit.app', 'repl.co', 'vercel.app', 'netlify.app', 'pages.dev', 'workers.dev',
  'github.io', 'gitlab.io', 'weebly.com', 'weeblysite.com', 'webflow.io', 'bubbleapps.io',
  'blogspot.com', 'wixsite.com', 'square.site', 'glitch.me', 'cloudwaysapps.com', 'godaddysites.com',
  'sugester.com', 'onrender.com', 'fly.dev', 'surge.sh', 'neocities.org',
];

/**
 * The self-chosen part of a host on shared hosting, or '' when the host is not
 * on one. e.g. mail-login-pt.weebly.com → 'mail-login-pt';
 * retunanet.z27.web.core.windows.net → 'retunanet.z27'.
 */
export function sharedHostingTenant(hostname) {
  const h = String(hostname || '').toLowerCase().replace(/\.$/, '');
  for (const suffix of SHARED_HOSTING_SUFFIXES) {
    if (h.endsWith(`.${suffix}`)) return h.slice(0, -(suffix.length + 1));
  }
  return '';
}

// Credential words only. A word that also reads as an honest product name
// (support, mail, update, billing, access, portal, app) is deliberately absent:
// it would flag a real tenant, and a false positive on a legitimate page is the
// one failure this detector cannot afford.
// 'auth' and 'app' are absent on purpose: next-auth-example.vercel.app is a real
// demo, and the dev-tooling world is full of honest auth tenants.
const TENANT_LURE_TOKENS = new Set([
  'login', 'signin', 'signon', 'logon', 'verify', 'verification', 'verified',
  'validate', 'validation', 'secure', 'security', 'account', 'accounts', 'webmail', 'password',
  'passwort', 'recovery', 'unlock', 'suspended', 'reactivate', 'confirmation',
  'acceso', 'ingresar', 'conectar', 'connexion', 'anmelden', 'seguridad', 'seguranca', 'verificacion',
]);

/** Tokens in a tenant label: split on separators and digit runs. */
function tenantTokens(tenant) {
  return String(tenant || '').toLowerCase().split(/[^a-z]+/).filter(Boolean);
}

/**
 * A tenant label that was thrown together rather than registered by an owner:
 * three or more words, a digit run, a doubled separator, or a machine-generated
 * label. MEASURED: without this conjunction the brand branch below flags the
 * brand's OWN official tenants (google.github.io, googleblog.blogspot.com,
 * microsoft.github.io and 31 more, the whole 2026-09-15 FP batch), because a
 * brand really does own `google.github.io`. An attacker's tenant is
 * `office-365-msn--oficeer` or `account-att-com-a96077`, never `google`.
 */
export function tenantLooksDisposable(tenant) {
  const t = String(tenant || '').toLowerCase();
  if (/--/.test(t)) return 'doubled-separator';
  if (/[0-9]{3,}/.test(t)) return 'digit-run';
  if (tenantTokens(t).length >= 3) return 'many-words';
  if (tenantLooksOpaque(t)) return 'machine-generated';
  return null;
}

export function tenantLureHit(tenant) {
  if (!tenantLooksDisposable(tenant)) return null;
  const squashed = String(tenant || '').toLowerCase().replace(/[^a-z0-9]/g, '');
  for (const token of tenantTokens(tenant)) {
    if (TENANT_LURE_TOKENS.has(token)) return { kind: 'credential-word', token };
  }
  // A brand is distinctive enough to read through the separators an attacker
  // sprinkles in (office-365-msn, account-att-com). An ordinary word is not,
  // which is why only the brand list gets this treatment.
  for (const brand of HIGH_VALUE_BRANDS) {
    if (brand.length >= 5 && squashed.includes(brand)) return { kind: 'brand', token: brand };
  }
  return null;
}

/** A tenant label that is machine-generated: a DGA stem or a long digit run. */
export function tenantLooksOpaque(tenant) {
  const t = String(tenant || '').toLowerCase();
  if (/[0-9]{10,}/.test(t)) return 'digit-run';
  for (const label of t.split('.')) {
    if (!/^xn--/.test(label) && looksAlgorithmicallyGenerated(label)) return 'machine-generated';
  }
  return null;
}

const EMAIL_IN_URL = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/i;

// A kit's own landing script: a server-side page whose file name OR the folder
// holding it is about signing in. Both halves are needed, because the file is as
// often `index.php` inside `/office/` as it is `login.php` at the top. Matched
// ONLY in conjunction with the victim's address in the link, never alone: plenty
// of honest sites serve wp-login.php.
const SCRIPT_FILE = /\.(?:php|aspx?|html?|cgi|jsp)$/i;
const CREDENTIAL_WORD = /(login|log-?in|signin|sign-?in|logon|auth|authen|verify|validate|secure|confirm|account|webmail|office|session|password|recover|unlock)/i;

export function looksCredentialPath(pathname) {
  const segments = String(pathname || '').split('/').filter(Boolean);
  const file = segments[segments.length - 1] || '';
  if (!SCRIPT_FILE.test(file)) return false;
  const folder = segments[segments.length - 2] || '';
  return CREDENTIAL_WORD.test(file) || CREDENTIAL_WORD.test(folder);
}

export function urlHeuristics(urlString) {
  const findings = [];
  let url;
  try {
    url = new URL(urlString);
  } catch {
    // Malformed URL with xn-- prefix is a strong IDN-spoofing signal.
    const looksLikePunycodeHomograph = /xn--/i.test(urlString || '');
    return {
      score: looksLikePunycodeHomograph ? 30 : 5,
      findings: [{
        id: 'invalid_url',
        severity: looksLikePunycodeHomograph ? 'medium' : 'low',
        message: looksLikePunycodeHomograph
          ? 'URL fails standard parsing and contains a punycode prefix — often a malformed IDN homograph.'
          : 'URL is malformed.',
      }],
    };
  }
  const host = url.hostname.toLowerCase();
  const tld = getTld(host);

  // v1.3.1 — curated safe domains short-circuit to a clean verdict. Stops the
  // heuristics from flagging major legit services and brand-owned infra.
  if (isSafeDomain(host)) {
    return { score: 0, findings: [], host, tld, registrable: getRegistrableDomain(host), safe: true };
  }

  if (url.protocol === 'http:') {
    findings.push({
      id: 'no_https',
      severity: 'medium',
      message: 'Page is served over plain HTTP. Any password or credit-card field on this page is exposed.',
    });
  }

  if (SUSPICIOUS_TLDS.has(tld)) {
    findings.push({
      id: 'suspicious_tld',
      severity: HIGH_ABUSE_TLDS.has(tld) ? 'high' : 'medium',
      message: `Top-level domain .${tld} is heavily abused for short-lived phishing kits.`,
    });
  }

  if (hasIdnHomograph(host)) {
    findings.push({
      id: 'idn_homograph',
      severity: 'high',
      message: 'Domain uses internationalized characters that can mimic ASCII letters.',
    });
  }

  const brandHits = looksLikeBrandImpersonation(host);
  for (const hit of brandHits) {
    findings.push({
      id: 'brand_impersonation',
      // A brand token in the registrable name is strong URL evidence. The
      // same token in a subdomain is common on legitimate institutional and
      // cloud estates (for example apple-repository.tudelft.nl), so it only
      // corroborates another signal. U7's DOM detector handles credential
      // pages on legitimate hosting platforms with its own conjunction.
      severity: hit.strength === 'corroborating' ? 'low' : 'high',
      message: `Domain looks like an impersonation of "${hit.brand}" (${hit.kind}).`,
      meta: hit,
    });
  }

  // IP literal as host
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.startsWith('[')) {
    findings.push({
      id: 'ip_host',
      severity: 'high',
      message: 'URL points to a raw IP address, not a domain.',
    });
  }

  // v1.11.0 — random / machine-generated registrable name (Francis bug). Analyse
  // the registrable second-level label so a random subdomain under a legit base
  // isn't penalised, and a random base domain is caught regardless of subdomain.
  const sld = getRegistrableDomain(host).split('.')[0] || '';
  // v1.11.0 FP fix — `URL.hostname` is punycode; an `xn--` stem is an encoded
  // Unicode IDN (飞利浦.jp, испытание.рф), NOT a machine-generated name. Never run
  // the latin-oriented DGA detector on a punycode stem or it reads every longer
  // CJK/Cyrillic IDN as 'random'. A clean ASCII stem (site2723vftu6f) still flags.
  if (!/^xn--/i.test(sld) && looksAlgorithmicallyGenerated(sld)) {
    findings.push({
      id: 'random_domain',
      severity: 'medium',
      message: 'Domain name looks randomly generated (letters and digits jumbled together) — a hallmark of short-lived phishing sites.',
    });
  }

  // Excessive subdomains, sometimes used to hide a brand inside a fake host.
  // v1.12.0 RECALIBRATED — this was `>=5 → medium`, i.e. 20 points, which on its own
  // met the `suspicious` cut. Deep subdomains are ordinary in enterprise and cloud
  // estates, so that flagged legitimate hosts with NO other signal
  // (my.account.portal.vlaanderen.be, eu-west-1.console.aws.example.com,
  // login.company.internal.example.com — all measured as false positives on
  // 2026-07-15). A deep chain is weak CORROBORATION, never evidence by itself: the
  // real attack (login.microsoft.account.security.gq) is caught by the brand + TLD
  // findings and still scores `phishing` with this demoted to `low`.
  // 4 labels is dropped entirely — www.foo.co.uk is a 4-label host.
  const labelCount = host.split('.').length;
  if (labelCount >= 6) {
    findings.push({
      id: 'deep_subdomain',
      severity: 'low',
      message: `Unusually deep subdomain chain (${labelCount} labels).`,
    });
  } else if (labelCount === 5) {
    findings.push({
      id: 'deep_subdomain',
      severity: 'low',
      message: `Slightly deep subdomain chain (${labelCount} labels).`,
    });
  }

  // Username:password embedded in URL
  if (url.username || url.password) {
    findings.push({
      id: 'embedded_credentials',
      severity: 'high',
      message: 'URL contains embedded credentials (`user:pass@host`). Strong phishing signal.',
    });
  }

  // PLAN-90 A3 — the tenant label on shared hosting (see the block above).
  const tenant = sharedHostingTenant(host);
  if (tenant) {
    const lure = tenantLureHit(tenant);
    if (lure) {
      findings.push({
        id: 'hosted_lure_label',
        severity: 'medium',
        message: lure.kind === 'brand'
          ? `This page is a free site on ${host.slice(tenant.length + 1)} whose address was made to read like "${lure.token}". Anyone can create one.`
          : `This page is a free site on ${host.slice(tenant.length + 1)} whose address was built around "${lure.token}". Anyone can create one.`,
        meta: lure,
      });
    }
    const opaque = tenantLooksOpaque(tenant);
    if (opaque) {
      findings.push({
        id: 'hosted_opaque_label',
        severity: 'medium',
        message: `This page is a free site on ${host.slice(tenant.length + 1)} with a machine-generated address, a shape short-lived phishing pages use.`,
        meta: { kind: opaque },
      });
    }
  }

  // PLAN-90 A4 — the victim's own address carried in the URL. In the fragment it
  // is the kit prefilling its form (the fragment never reaches a server, so no
  // honest backend can be using it); in the query it is common in legitimate
  // mailing links, so there it only counts together with a credential file name.
  const emailInFragment = EMAIL_IN_URL.test(url.hash || '');
  const emailInQuery = EMAIL_IN_URL.test(decodeURIComponent(url.search || ''));
  const credentialFile = looksCredentialPath(url.pathname || '');
  if (emailInFragment) {
    findings.push({
      id: 'email_in_fragment',
      severity: 'medium',
      message: 'The address bar already carries an email address after the # sign, which is how a fake sign-in page fills in your name before you type it.',
    });
  } else if (emailInQuery && credentialFile) {
    findings.push({
      id: 'email_in_credential_url',
      severity: 'medium',
      message: 'This sign-in page was opened with an email address already in the link, which is how a fake sign-in page fills in your name before you type it.',
    });
  }

  // Long URL with tracking-style query soup
  if (urlString.length > 250) {
    findings.push({
      id: 'long_url',
      severity: 'low',
      message: 'URL is unusually long, often used to hide the real domain.',
    });
  }

  const score = findings.reduce((acc, f) => {
    return acc + ({ low: 5, medium: 20, high: 40 }[f.severity] || 0);
  }, 0);

  return { score, findings, host, tld, registrable: getRegistrableDomain(host) };
}

export function verdictFromScore(score, options = {}) {
  // Phishing Detector mode lowers thresholds — flags faster, blocks earlier.
  const phishingMode = options.phishingMode === true;
  let phishCut = phishingMode ? 45 : 60;
  let suspectCut = phishingMode ? 10 : 20;
  // v1.6.0 — the options-page Sensitivity select finally has teeth.
  // 'paranoid' tightens both cuts; 'lenient' relaxes them. 'balanced' (or
  // unset) keeps the calibrated defaults, so the eval gate is unaffected.
  if (options.sensitivity === 'paranoid') {
    phishCut -= 10;
    suspectCut -= 5;
  } else if (options.sensitivity === 'lenient') {
    phishCut += 15;
    suspectCut += 10;
  }
  let verdict = score >= phishCut ? 'phishing' : score >= suspectCut ? 'suspicious' : 'safe';

  // v1.10.0 — fuse a cloud AI verdict, ESCALATE-ONLY. The AI can RAISE risk but
  // must never silently downgrade a heuristic phishing/suspicious to safe, and an
  // abstain ('unknown') or low-confidence verdict never lowers the floor. This is
  // the trust-spine + the adversarial-review rule: an injected/abstaining model
  // can never turn a flagged email "safe".
  const RANK = { safe: 0, suspicious: 2, phishing: 3 };
  const ai = options.aiVerdict;
  const aiConf = typeof options.aiConfidence === 'number' ? options.aiConfidence : 0;
  if (ai && ai !== 'unknown' && RANK[ai] != null && RANK[ai] > RANK[verdict]) {
    if (ai === 'phishing' && aiConf >= 0.6) verdict = 'phishing';
    else if (ai === 'suspicious' && aiConf >= 0.5) verdict = 'suspicious';
  }
  return verdict;
}

// v1.11.0 — pure dimension fit for screenshot minimization. Scales a capture so
// its longest edge is at most `maxDim` px, preserving aspect ratio. Pure + no
// canvas, so it is unit-testable; `minimizeScreenshot()` in the service worker
// feeds OffscreenCanvas with the result. CRITICAL must-fix #1: a vision capture
// must never ship a full-resolution screenshot of an arbitrary page.
export function fitDimensions(width, height, maxDim = 1024) {
  const w = Math.max(1, Math.round(width) || 1);
  const h = Math.max(1, Math.round(height) || 1);
  const longest = Math.max(w, h);
  if (longest <= maxDim) return { width: w, height: h, scale: 1 };
  const scale = maxDim / longest;
  return {
    width: Math.max(1, Math.round(w * scale)),
    height: Math.max(1, Math.round(h * scale)),
    scale,
  };
}

// v1.11.0 — vision-escalation gate. CRITICAL must-fixes #1 + #8: never blindly
// screenshot an arbitrary page. A capture is only justified when the page is a
// PLAUSIBLE phishing target the cloud tier can actually inspect. Pure function so
// every trigger (nav / activation / mutation / safety alarm) shares one rule and
// it is unit-testable. Returns { capture, code } — `code` explains the decision.
//
// Order matters (cheapest + most-protective checks first):
//   manual      → always capture (the user explicitly asked; bypasses the gate)
//   signed-out  → skip (vision is a sign-in + consent-gated cloud tier; capturing
//                 a screenshot we cannot send is waste AND an avoidable exposure)
//   non-web     → skip (only http/https pages are scannable)
//   safe-domain → skip (the #1 Limited-Use leak: screenshotting the user's bank /
//                 health / password page on a curated-legit domain)
//   already-phishing → skip (we've adjudicated + acted; re-capturing adds nothing)
//   no-signal   → skip (no medium+ URL heuristic finding and no credential/brand
//                 DOM signal — pointing the camera here is unjustified)
export function shouldEscalateToVision({
  url,
  signedIn = false,
  reason = 'periodic',
  heuristics = null,
  cachedVerdict = null,
  hasContentSignal = false,
} = {}) {
  if (reason === 'manual' || reason === 'scan-now') return { capture: true, code: 'manual' };
  if (!signedIn) return { capture: false, code: 'signed-out' };
  if (!url || !/^https?:/i.test(url)) return { capture: false, code: 'non-web' };
  if (heuristics?.safe === true) return { capture: false, code: 'safe-domain' };
  if (cachedVerdict?.verdict === 'phishing') return { capture: false, code: 'already-phishing' };

  const urlSignal = Array.isArray(heuristics?.findings)
    && heuristics.findings.some((f) => f && (f.severity === 'high' || f.severity === 'medium'));
  if (!urlSignal && !hasContentSignal) return { capture: false, code: 'no-signal' };

  return { capture: true, code: 'signal' };
}

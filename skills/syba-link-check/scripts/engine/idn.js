// SYBA Shield — IDN / punycode analysis for homograph detection (v1.3.2).
//
// Why this exists: `URL.hostname` returns the ASCII *punycode* form of an
// internationalized domain (müller.de -> www.xn--mller-kva.de). Treating any
// `xn--` host as a homograph attack false-flagged EVERY legitimate
// internationalized domain — café.fr, zürich.ch, société.be, 日本.jp — which is
// most of the non-English web and squarely SYBA's EU market.
//
// The real signal for a homograph spoof is SCRIPT MIXING: an attacker swaps one
// Latin letter for a confusable from another script (pаypal — Cyrillic а), or
// builds a whole label in a confusable script that reads as a Latin brand
// (аррӏе = "apple"). A genuine IDN is single-script: Latin-with-diacritics, or
// all-Cyrillic, or all-CJK. So we decode, then flag only mixed-script labels and
// confusable-folded brand collisions — never a clean single-script domain.
//
// Pure, dependency-free. Safe in a service worker, content script, or Node.

// ── Minimal RFC 3492 punycode decoder ──────────────────────────────────────
// Decodes a single label's payload (the part after the `xn--` prefix) to its
// Unicode string. Returns the original input on any malformed sequence.
const BASE = 36, T_MIN = 1, T_MAX = 26, SKEW = 38, DAMP = 700;
const INITIAL_BIAS = 72, INITIAL_N = 128, MAX_INT = 0x7fffffff;
const BASE_MINUS_TMIN = BASE - T_MIN;

function adaptBias(delta, numPoints, firstTime) {
  delta = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > (BASE_MINUS_TMIN * T_MAX) >> 1) {
    delta = Math.floor(delta / BASE_MINUS_TMIN);
    k += BASE;
  }
  return Math.floor(k + (BASE_MINUS_TMIN + 1) * delta / (delta + SKEW));
}

function basicToDigit(codePoint) {
  if (codePoint - 48 < 10) return codePoint - 22; // 0-9 -> 26..35
  if (codePoint - 65 < 26) return codePoint - 65; // A-Z -> 0..25
  if (codePoint - 97 < 26) return codePoint - 97; // a-z -> 0..25
  return BASE;
}

function punyDecode(input) {
  const output = [];
  let n = INITIAL_N;
  let i = 0;
  let bias = INITIAL_BIAS;

  let basic = input.lastIndexOf('-');
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; j++) {
    const c = input.charCodeAt(j);
    if (c >= 0x80) throw new Error('not-basic');
    output.push(c);
  }

  for (let index = basic > 0 ? basic + 1 : 0; index < input.length; /* */) {
    const oldi = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (index >= input.length) throw new Error('invalid-input');
      const digit = basicToDigit(input.charCodeAt(index++));
      if (digit >= BASE || digit > Math.floor((MAX_INT - i) / w)) throw new Error('overflow');
      i += digit * w;
      const t = k <= bias ? T_MIN : (k >= bias + T_MAX ? T_MAX : k - bias);
      if (digit < t) break;
      const baseMinusT = BASE - t;
      if (w > Math.floor(MAX_INT / baseMinusT)) throw new Error('overflow');
      w *= baseMinusT;
    }
    const out = output.length + 1;
    bias = adaptBias(i - oldi, out, oldi === 0);
    if (Math.floor(i / out) > MAX_INT - n) throw new Error('overflow');
    n += Math.floor(i / out);
    i %= out;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

/**
 * Decode a hostname's `xn--` labels to their Unicode form. Non-IDN labels and
 * malformed punycode pass through unchanged.
 * @param {string} hostname
 * @returns {string}
 */
export function decodeIdnHostname(hostname) {
  if (!hostname || hostname.indexOf('xn--') === -1) return hostname || '';
  return hostname.split('.').map((label) => {
    if (!/^xn--/i.test(label)) return label;
    try {
      return punyDecode(label.slice(4).toLowerCase());
    } catch {
      return label; // leave malformed punycode as-is; caller treats it as risky
    }
  }).join('.');
}

// ── Script-family classification ────────────────────────────────────────────
// We only need to tell apart the families that matter for spoofing. ASCII and
// Latin-with-diacritics are one family ("latin"); the confusable scripts
// (Cyrillic, Greek) and CJK each get their own bucket. Digits, hyphens and
// combining marks are script-neutral and ignored.
function charScript(cp) {
  if (cp < 0x80) {
    // letters only; digits/hyphen/dot are neutral
    if ((cp >= 0x41 && cp <= 0x5a) || (cp >= 0x61 && cp <= 0x7a)) return 'latin';
    return null;
  }
  if ((cp >= 0xc0 && cp <= 0x24f) || (cp >= 0x1e00 && cp <= 0x1eff)) return 'latin'; // Latin-1 Supp + Latin Extended A/B + Additional
  if (cp >= 0x0300 && cp <= 0x036f) return null;                                     // combining diacritical marks (neutral)
  if (cp >= 0x0370 && cp <= 0x03ff) return 'greek';
  if (cp >= 0x0400 && cp <= 0x04ff) return 'cyrillic';
  if (cp >= 0x0500 && cp <= 0x052f) return 'cyrillic';                               // Cyrillic Supplement
  return 'other'; // CJK, Arabic, Hebrew, Thai, Devanagari, symbols, ...
}

/**
 * Set of script families used by the *letters* of a single decoded label.
 * @param {string} label
 * @returns {Set<string>}
 */
export function scriptFamilies(label) {
  const fams = new Set();
  for (const ch of String(label)) {
    const s = charScript(ch.codePointAt(0));
    if (s) fams.add(s);
  }
  return fams;
}

/**
 * True when a decoded hostname contains a homoglyph-risk label: one that mixes
 * Latin with a non-Latin script, or mixes two different non-Latin scripts
 * within the same label. Clean single-script labels (legit IDNs) return false.
 * @param {string} unicodeHostname  hostname already run through decodeIdnHostname
 * @returns {boolean}
 */
export function hasMixedScriptLabel(unicodeHostname) {
  for (const label of String(unicodeHostname).split('.')) {
    const fams = scriptFamilies(label);
    if (fams.size >= 2) return true; // e.g. {latin, cyrillic} or {latin, other}
  }
  return false;
}

// Confusable characters (Cyrillic / Greek / look-alike forms) → ASCII skeleton.
// Used to detect whole-script brand spoofs (аррӏе → apple) that are single-script
// and so slip past the mixed-script check. Intentionally small and high-signal —
// only glyphs that genuinely read as a Latin letter.
const CONFUSABLE = {
  // Cyrillic
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'ѕ': 's', 'і': 'i', 'ї': 'i',
  'ј': 'j', 'ӏ': 'l', 'һ': 'h', 'ԁ': 'd', 'у': 'y', 'х': 'x', 'к': 'k', 'м': 'm',
  'т': 't', 'в': 'b', 'н': 'h', 'г': 'r', 'ё': 'e', 'ԛ': 'q', 'ѡ': 'w', 'ɡ': 'g',
  // Greek
  'ο': 'o', 'ρ': 'p', 'α': 'a', 'ϲ': 'c', 'ε': 'e', 'ι': 'i', 'ν': 'v', 'τ': 't',
  'υ': 'u', 'κ': 'k', 'β': 'b', 'η': 'n', 'χ': 'x',
};

/**
 * Fold confusable non-ASCII letters to their Latin skeleton and lowercase.
 * Pure-ASCII input is returned unchanged (lowercased), so this never invents
 * brand collisions for ordinary domains.
 *
 * v1.13.0 — also folds FULLWIDTH Latin (U+FF21–FF3A / U+FF41–FF5A). Fullwidth
 * forms (ｐａｙｐａｌ) render as ordinary Latin at a glance and are a documented
 * homoglyph vector, yet a fullwidth-only label is single-script ("other" family)
 * so it slips past the mixed-script check — folding it here routes it into the
 * brand-collision path. The mapping is unambiguous (Ａ↔A) so it invents no
 * collision for a genuine ASCII domain, which is never fullwidth.
 * @param {string} s
 * @returns {string}
 */
export function foldConfusables(s) {
  let out = '';
  for (const ch of String(s).toLowerCase()) {
    if (CONFUSABLE[ch]) { out += CONFUSABLE[ch]; continue; }
    const cp = ch.codePointAt(0);
    // Fullwidth lowercase a–z (U+FF41–FF5A). Uppercase folds to lowercase first
    // via toLowerCase() above, so only the lowercase range needs handling here.
    if (cp >= 0xff41 && cp <= 0xff5a) { out += String.fromCharCode(cp - 0xff41 + 0x61); continue; }
    out += ch;
  }
  return out;
}

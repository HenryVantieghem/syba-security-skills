// SYBA Shield — "Ask SYBA about this screen": what must never leave the device (pure).
//
// A screenshot is sent to the AI scan backend only after every region that
// could hold a secret has been painted black. This file decides WHICH regions.
// It does no I/O and touches no DOM: content/ask-screen.js feeds it field
// descriptors and text, and the service worker feeds it the page title.
//
// FAIL-CLOSED CONTRACT (enforced by background/background.js, not here): when
// this layer cannot run, or says its pass was incomplete, no screenshot is
// uploaded. Nothing in this file reports "clean" for something it could not see.
//
// WHAT IT CATCHES. Fields: password, card and one-time-code inputs by type,
// autocomplete token or name. Text: Luhn-valid card numbers, mod-97-valid IBANs,
// US SSNs, API-key and token shapes, and emails only when asked (a managed
// `redactEmails` policy or the caller's choice). Frames: payment-processor
// iframes, whose insides a content script in the top frame cannot read.
//
// WHAT IT DOES NOT CLAIM. Text drawn into a canvas or an image is not text and
// is not seen here; the screenshot is still downscaled to 1024px before upload
// like every other capture. The privacy copy says "redacts card numbers,
// password fields and obvious secrets", not "removes everything sensitive".
//
// DUAL-MODE classic script, like lib/qr-signals.js: assigns globalThis.SYBA_ASK_REDACT.
// No import/export, so it loads as a content script and via `new Function` in tests.

(function (root) {
  'use strict';

  /** Cap on rectangles sent to the painter; a page with more is treated as incomplete. */
  const MAX_RECTS = 300;
  /** CSS px of margin around each box, so anti-aliased glyph edges are covered. */
  const PAD_PX = 4;

  /** Hosts whose iframes carry card entry. The top frame cannot read inside them. */
  const PAYMENT_FRAME_HOST = /(^|\.)(stripe\.com|stripe\.network|paypal\.com|paypalobjects\.com|adyen\.com|braintreegateway\.com|braintree-api\.com|squareup\.com|squarecdn\.com|klarna\.com|recurly\.com|authorize\.net|checkout\.com|mollie\.com|worldpay\.com|cybersource\.com)$/i;

  /** Field names that mean "secret" however the site spelled the markup. */
  const SENSITIVE_NAME = /(card.?n(um|umber|o)\b|cc.?(num|number)|cardnumber|\bcvv\b|\bcvc\b|\bcsc\b|security.?code|iban|routing.?n|account.?n(um|umber)|\bssn\b|social.?security|passcode|passwd|\bpin\b|\botp\b|one.?time|2fa|verification.?code|seed.?phrase|recovery.?phrase|private.?key|api.?key|secret)/i;
  const SENSITIVE_AUTOCOMPLETE = /(^|\s)(cc-[a-z-]+|current-password|new-password|one-time-code)(\s|$)/i;

  const PATTERNS = {
    card: /(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])/g,
    iban: /\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b/g,
    ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
    secret: /\b(?:[sprk]k_(?:live|test)_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|AKIA[0-9A-Z]{16}|xox[abprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b/g,
    email: /[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}/g,
  };

  /** Luhn checksum over a digit string. */
  function luhnValid(digits) {
    const s = String(digits || '');
    if (!/^\d+$/.test(s)) return false;
    let sum = 0;
    let dbl = false;
    for (let i = s.length - 1; i >= 0; i--) {
      let d = s.charCodeAt(i) - 48;
      if (dbl) { d *= 2; if (d > 9) d -= 9; }
      sum += d;
      dbl = !dbl;
    }
    return s.length > 0 && sum % 10 === 0;
  }

  /** ISO 13616 mod-97 check; keeps arbitrary "AB12 ..." text from being masked as an IBAN. */
  function ibanValid(raw) {
    const s = String(raw || '').replace(/\s+/g, '').toUpperCase();
    if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(s)) return false;
    const moved = s.slice(4) + s.slice(0, 4);
    let rem = 0;
    for (const ch of moved) {
      const part = ch >= 'A' ? String(ch.charCodeAt(0) - 55) : ch;
      for (const digit of part) rem = (rem * 10 + (digit.charCodeAt(0) - 48)) % 97;
    }
    return rem === 1;
  }

  function ssnValid(raw) {
    const m = /^(\d{3})-(\d{2})-(\d{4})$/.exec(String(raw || ''));
    if (!m) return false;
    const [, area, group, serial] = m;
    return area !== '000' && area !== '666' && area[0] !== '9' && group !== '00' && serial !== '0000';
  }

  /**
   * Sensitive spans inside a string, in document order, non-overlapping.
   * @param {string} text
   * @param {{emails?: boolean}} [opts]
   * @returns {{kind: string, start: number, end: number}[]}
   */
  function findSensitive(text, opts) {
    const src = typeof text === 'string' ? text : '';
    if (!src) return [];
    const wantEmails = !!(opts && opts.emails);
    const found = [];
    const scan = (kind, re, ok) => {
      re.lastIndex = 0;
      let m;
      while ((m = re.exec(src)) !== null) {
        if (m[0].length === 0) { re.lastIndex += 1; continue; }
        if (ok(m[0])) found.push({ kind, start: m.index, end: m.index + m[0].length });
      }
    };
    scan('card', PATTERNS.card, (s) => {
      const digits = s.replace(/[ -]/g, '');
      return digits.length >= 13 && digits.length <= 19 && luhnValid(digits);
    });
    scan('iban', PATTERNS.iban, ibanValid);
    scan('ssn', PATTERNS.ssn, ssnValid);
    scan('secret', PATTERNS.secret, () => true);
    if (wantEmails) scan('email', PATTERNS.email, () => true);

    found.sort((a, b) => a.start - b.start || b.end - a.end);
    const out = [];
    for (const f of found) {
      const last = out[out.length - 1];
      if (last && f.start < last.end) { last.end = Math.max(last.end, f.end); continue; }
      out.push({ ...f });
    }
    return out;
  }

  /** The same string with every sensitive span replaced. For titles and URLs only. */
  function redactText(text, opts) {
    const src = typeof text === 'string' ? text : '';
    const spans = findSensitive(src, opts);
    if (!spans.length) return src;
    let out = '';
    let at = 0;
    for (const s of spans) { out += src.slice(at, s.start) + '[redacted]'; at = s.end; }
    return out + src.slice(at);
  }

  /**
   * Origin and path only. A query string or fragment is where session tokens,
   * reset codes and email addresses ride, and the backend does not need them.
   * Anything that is not an http(s) URL becomes ''.
   */
  function minimizeUrl(url) {
    try {
      const u = new URL(String(url || ''));
      if (u.protocol !== 'https:' && u.protocol !== 'http:') return '';
      return `${u.protocol}//${u.host}${u.pathname}`.slice(0, 500);
    } catch {
      return '';
    }
  }

  /**
   * Is this form control one whose contents must be masked?
   * @param {{type?: string, autocomplete?: string, name?: string, id?: string, placeholder?: string, ariaLabel?: string}} f
   * @param {{emails?: boolean}} [opts]
   */
  function fieldIsSensitive(f, opts) {
    if (!f || typeof f !== 'object') return false;
    const type = String(f.type || '').toLowerCase();
    if (type === 'password') return true;
    if (type === 'email' && opts && opts.emails) return true;
    if (SENSITIVE_AUTOCOMPLETE.test(String(f.autocomplete || ''))) return true;
    const label = [f.name, f.id, f.placeholder, f.ariaLabel].map((v) => String(v || '')).join(' ');
    return SENSITIVE_NAME.test(label);
  }

  /** Does this iframe src point at a card-entry frame? */
  function isPaymentFrame(src) {
    try {
      return PAYMENT_FRAME_HOST.test(new URL(String(src || ''), 'https://invalid.example/').hostname);
    } catch {
      return false;
    }
  }

  /**
   * A viewport-relative rect (CSS px) as fractions of the viewport, padded and
   * clamped to [0,1]. Fractions survive the downscale between the page and the
   * uploaded image, so the painter needs no devicePixelRatio. Null when the box
   * has no area inside the viewport.
   */
  function toFraction(rect, vw, vh) {
    if (!rect || !(vw > 0) || !(vh > 0)) return null;
    const x0 = Math.max(0, (Number(rect.x) - PAD_PX) / vw);
    const y0 = Math.max(0, (Number(rect.y) - PAD_PX) / vh);
    const x1 = Math.min(1, (Number(rect.x) + Number(rect.w) + PAD_PX) / vw);
    const y1 = Math.min(1, (Number(rect.y) + Number(rect.h) + PAD_PX) / vh);
    if (![x0, y0, x1, y1].every(Number.isFinite) || x1 <= x0 || y1 <= y0) return null;
    return { x: x0, y: y0, w: x1 - x0, h: y1 - y0, kind: rect.kind || 'field' };
  }

  /** Fractions to pixel rects for an image of the given size. */
  function toPixelRects(fracs, width, height) {
    const out = [];
    for (const f of Array.isArray(fracs) ? fracs : []) {
      const x = Math.floor(Math.max(0, Math.min(1, Number(f.x))) * width);
      const y = Math.floor(Math.max(0, Math.min(1, Number(f.y))) * height);
      const w = Math.ceil(Math.max(0, Math.min(1, Number(f.w))) * width) + 1;
      const h = Math.ceil(Math.max(0, Math.min(1, Number(f.h))) * height) + 1;
      if (![x, y, w, h].every(Number.isFinite) || w <= 1 || h <= 1) continue;
      out.push({ x, y, w: Math.min(w, width - x), h: Math.min(h, height - y), kind: f.kind || 'field' });
    }
    return out;
  }

  root.SYBA_ASK_REDACT = {
    MAX_RECTS, PAD_PX,
    luhnValid, ibanValid, ssnValid, findSensitive, redactText, minimizeUrl,
    fieldIsSensitive, isPaymentFrame, toFraction, toPixelRects,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);

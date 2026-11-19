// Minimal RFC 5322 / MIME reader for .eml files and pasted message sources.
// Pulls out what the SYBA email detectors read: the sender's display name and
// address, the subject, the visible body text, and every link with its visible
// text. No network, no attachments opened. Ported from the SYBA desktop app.

function unfoldHeaders(head) {
  const map = new Map();
  const lines = head.replace(/\r\n/g, '\n').split('\n');
  let cur = '';
  const flush = () => {
    const i = cur.indexOf(':');
    if (i > 0) {
      const k = cur.slice(0, i).trim().toLowerCase();
      if (!map.has(k)) map.set(k, cur.slice(i + 1).trim());
    }
  };
  for (const l of lines) {
    if (/^[ \t]/.test(l)) cur += ' ' + l.trim();
    else { if (cur) flush(); cur = l; }
  }
  if (cur) flush();
  return map;
}

function bytesToUtf8(bytes) {
  return new TextDecoder('utf-8').decode(new Uint8Array(bytes));
}

function b64Bytes(s) {
  return [...Buffer.from(s.replace(/[^A-Za-z0-9+/=]/g, ''), 'base64')];
}

function qpBytes(s) {
  const t = s.replace(/=\r?\n/g, '');
  const out = [];
  for (let i = 0; i < t.length; i++) {
    if (t[i] === '=' && /^[0-9A-Fa-f]{2}$/.test(t.slice(i + 1, i + 3))) { out.push(parseInt(t.slice(i + 1, i + 3), 16)); i += 2; }
    else out.push(...Buffer.from(t[i], 'utf8'));
  }
  return out;
}

/** RFC 2047 encoded words: =?utf-8?B?...?= and =?utf-8?Q?...?= */
export function decodeWords(s) {
  return String(s || '').replace(/=\?([^?]+)\?([bBqQ])\?([^?]*)\?=\s*/g, (_m, _cs, enc, data) => {
    const bytes = enc.toUpperCase() === 'B' ? b64Bytes(data) : qpBytes(data.replace(/_/g, ' '));
    return bytesToUtf8(bytes);
  }).trim();
}

export function parseAddress(v) {
  const s = decodeWords(v);
  const m = s.match(/^\s*"?([^"<]*?)"?\s*<([^>]+)>/);
  if (m) return { name: m[1].trim(), email: m[2].trim().toLowerCase() };
  const e = s.match(/[^\s<>"]+@[^\s<>"]+/);
  return e ? { name: '', email: e[0].toLowerCase() } : null;
}

function decodeBody(body, cte) {
  const enc = (cte || '').toLowerCase();
  if (enc.includes('base64')) return bytesToUtf8(b64Bytes(body));
  if (enc.includes('quoted-printable')) return bytesToUtf8(qpBytes(body));
  return body;
}

const ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };
export function decodeEntities(s) {
  return s.replace(/&(#x?[0-9a-f]+|[a-z]+);/gi, (m, e) => {
    if (e[0] === '#') {
      const n = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
      return Number.isFinite(n) ? String.fromCodePoint(n) : m;
    }
    return ENTITIES[e.toLowerCase()] ?? m;
  });
}

export function htmlToText(html) {
  return decodeEntities(
    html
      .replace(/<(script|style|head)[\s\S]*?<\/\1>/gi, ' ')
      .replace(/<br\s*\/?>/gi, '\n')
      .replace(/<\/(p|div|tr|li|h[1-6])>/gi, '\n')
      .replace(/<[^>]+>/g, ' '),
  ).replace(/[ \t]+/g, ' ').replace(/\n\s*\n+/g, '\n').trim();
}

function htmlLinks(html) {
  const out = [];
  const re = /<a\b[^>]*?href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a>/gi;
  let m;
  while ((m = re.exec(html)) && out.length < 60) {
    const href = decodeEntities((m[1] ?? m[2] ?? m[3] ?? '').trim());
    const text = htmlToText(m[4] || '').replace(/\s+/g, ' ').trim();
    if (/^https?:/i.test(href)) out.push({ text, href });
  }
  return out;
}

function splitPart(raw) {
  const norm = raw.replace(/\r\n/g, '\n');
  const i = norm.indexOf('\n\n');
  if (i < 0) return { headers: unfoldHeaders(norm), body: '' };
  return { headers: unfoldHeaders(norm.slice(0, i)), body: norm.slice(i + 2) };
}

function walk(raw, acc, depth = 0) {
  if (depth > 6) return;
  const { headers, body } = splitPart(raw);
  const ctype = headers.get('content-type') || 'text/plain';
  const boundary = ctype.match(/boundary\s*=\s*"?([^";]+)"?/i)?.[1];
  if (/^multipart\//i.test(ctype) && boundary) {
    const parts = body.split(new RegExp(`\\n?--${boundary.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:--)?[ \\t]*\\n?`));
    for (const p of parts) if (p.trim()) walk(p, acc, depth + 1);
    return;
  }
  if (/attachment/i.test(headers.get('content-disposition') || '')) return;
  const decoded = decodeBody(body, headers.get('content-transfer-encoding') || '');
  if (/text\/html/i.test(ctype)) acc.html.push(decoded);
  else if (/text\/plain/i.test(ctype) || !headers.has('content-type')) acc.text.push(decoded);
}

/** True when the text starts with RFC 5322 headers (a real .eml or "show original"). */
export function looksLikeEml(raw) {
  const head = String(raw || '').replace(/\r\n/g, '\n').split('\n\n')[0];
  return /^(from|subject|received|return-path|delivered-to|message-id|date|to|mime-version):/im.test(head)
    && /^from:/im.test(head);
}

export function parseEml(raw) {
  const src = String(raw || '');
  const { headers } = splitPart(src);
  const acc = { html: [], text: [] };
  walk(src, acc);
  const html = acc.html.join('\n');
  const links = htmlLinks(html);
  if (!links.length) {
    for (const t of acc.text) for (const m of t.matchAll(/https?:\/\/[^\s<>"')]+/g)) links.push({ text: m[0], href: m[0] });
  }
  const text = (acc.text.length ? acc.text.join('\n') : htmlToText(html)).slice(0, 20000);
  return {
    from: parseAddress(headers.get('from') || ''),
    replyTo: parseAddress(headers.get('reply-to') || ''),
    subject: decodeWords(headers.get('subject') || ''),
    date: headers.get('date') || '',
    authResults: headers.get('authentication-results') || '',
    text,
    links: links.slice(0, 60),
  };
}

/** A pasted email with no headers: body text, plus optional "From" line. */
export function parsePasted(raw, from) {
  const src = String(raw || '');
  const isHtml = /<a\b[^>]*href/i.test(src) || /<html|<body|<p>/i.test(src);
  const links = isHtml ? htmlLinks(src) : [];
  if (!isHtml) for (const m of src.matchAll(/https?:\/\/[^\s<>"')\]]+/g)) links.push({ text: m[0], href: m[0] });
  // Markdown links [text](url) keep their visible text.
  for (const m of src.matchAll(/\[([^\]]{1,200})\]\((https?:\/\/[^\s)]+)\)/g)) links.push({ text: m[1].trim(), href: m[2] });
  let sender = from ? parseAddress(from) : null;
  if (!sender) {
    const line = src.match(/^\s*from:\s*(.+)$/im);
    if (line) sender = parseAddress(line[1]);
  }
  const subj = src.match(/^\s*subject:\s*(.+)$/im);
  return {
    from: sender,
    replyTo: null,
    subject: subj ? subj[1].trim() : '',
    date: '',
    authResults: '',
    text: (isHtml ? htmlToText(src) : src).slice(0, 20000),
    links: links.slice(0, 60),
  };
}

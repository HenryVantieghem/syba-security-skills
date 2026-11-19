// SYBA Shield — clipboard-execution ("ClickFix") signals (pure, no DOM / no chrome.*).
//
// THE ATTACK: a page shows a fake CAPTCHA, a fake browser error, or a fake
// "verify you are human" step, silently writes a command to the clipboard, and
// instructs the user to paste it into the Run dialog or a terminal. The user
// becomes the delivery mechanism. Mimecast recorded a 500% rise in the first
// half of 2025, and it defeats every URL-based control this product has, because
// at the moment that matters there is no malicious URL to score — the page the
// user is on may be entirely unremarkable.
//
// WHY THE CONJUNCTION IS THE WHOLE DESIGN (same rule as lib/injection-signals.js):
//   A command-shaped clipboard write ALONE is developer documentation. Every
//   install page on the internet offers `curl … | sh` behind a copy button, and
//   flagging those would make the product unusable for the people most likely to
//   evaluate it.
//   Run-dialog instructions ALONE are ordinary prose — support articles explain
//   Win+R constantly.
// Only the two together, close in time, are the attack. Neither alone may fire.
//
// TIMING IS THE POINT. The warning is worth nothing after the paste, so the
// signal is raised on the clipboard WRITE, not on any later observation. That is
// also why classification happens here, on a payload the shim has already seen,
// rather than by reading the user's clipboard: SYBA never reads the clipboard.
// It observes what a page puts there, and only the SHAPE crosses out of the page
// context.
//
// DUAL-MODE: loaded as a classic script (assigns globalThis.SYBA_CLIPBOARD_EXEC,
// declared in the manifest BEFORE content/content.js) AND evaluated in Node by
// the suite via `new Function`. Do NOT add import/export.

(function (root) {
  'use strict';

  // Command shapes that only make sense pasted into a shell or a Run box.
  // Deliberately narrow: each is an EXECUTION construct, not merely a word that
  // appears in code samples.
  const EXEC_SHAPES = [
    { kind: 'powershell', re: /\b(?:powershell|pwsh)(?:\.exe)?\b[^\n]{0,120}?\s-(?:e(?:nc(?:odedcommand)?)?|c(?:ommand)?|nop|noprofile|w(?:indowstyle)?\s+hidden|ep|executionpolicy)\b/i },
    { kind: 'powershell', re: /\b(?:iex|invoke-expression)\b[\s(]*[^\n]{0,80}?(?:iwr|invoke-webrequest|new-object\s+net\.webclient|downloadstring)/i },
    { kind: 'powershell', re: /\b(?:iwr|invoke-webrequest|curl)\b[^\n]{0,120}?\|\s*(?:iex|invoke-expression)\b/i },
    { kind: 'run-dialog', re: /^\s*(?:cmd(?:\.exe)?|powershell(?:\.exe)?|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|msiexec)\b/i },
    { kind: 'run-dialog', re: /\bmshta\s+(?:https?|javascript):/i },
    { kind: 'shell-pipe', re: /\b(?:curl|wget)\b[^\n]{0,160}?\|\s*(?:sudo\s+)?(?:ba)?sh\b/i },
    { kind: 'shell-pipe', re: /\b(?:curl|wget)\b[^\n]{0,160}?\|\s*(?:python3?|perl|ruby|node)\b/i },
    { kind: 'encoded', re: /\b-e(?:nc|ncodedcommand)?\s+[A-Za-z0-9+/]{40,}={0,2}/i },
    { kind: 'encoded', re: /\b(?:FromBase64String|atob|base64\s+-d)\b[^\n]{0,80}?[A-Za-z0-9+/]{40,}/i },
    { kind: 'osascript', re: /\bosascript\s+-e\b/i },
    { kind: 'clipboard-marker', re: /(?:^|\s)(?:✅|✔|√)\s*["'“”]?(?:I am not a robot|Verify(?:ication)?)/i },
  ];

  // On-page instructions telling the user to EXECUTE what was copied. These are
  // the second leg; without one, a command-shaped payload is documentation.
  const EXEC_INSTRUCTIONS = [
    /\b(?:press|hit|hold)\s+(?:the\s+)?(?:windows?|win|⊞|⌘|command|cmd)\s*(?:key)?\s*(?:\+|and|then)?\s*[rvx]\b/i,
    /\bwin\s*\+\s*r\b/i,
    /\b(?:ctrl|control|⌘|cmd|command)\s*\+\s*v\b[^.]{0,60}?\b(?:then|and)\s+(?:press\s+)?enter\b/i,
    /\bopen\s+(?:the\s+)?(?:run\s+dialog|run\s+box|terminal|command\s+prompt|powershell|cmd)\b/i,
    /\bpaste\b[^.]{0,60}?\b(?:and\s+)?(?:press|hit)\s+enter\b/i,
    /\bpaste\s+(?:it|this|the\s+(?:code|command|text))\s+(?:in|into)\b/i,
    /\b(?:verify|prove)\s+you(?:'re| are)\s+(?:a\s+)?human\b[^.]{0,120}?\bpaste\b/i,
    /\bto\s+(?:fix|resolve|continue|verify)\b[^.]{0,80}?\bpaste\b/i,
  ];

  // Fake-verification framing. Not required, but it is what turns a suspicious
  // pair into an unmistakable one, and it is the shape users report.
  const FAKE_VERIFY = [
    /\b(?:i am not a robot|i'm not a robot|verify you are human|human verification|cloudflare|ray id|checking your browser)\b/i,
    /\b(?:error|failed) (?:code|id)\s*[:#]?\s*[a-z0-9-]{4,}/i,
    /\b(?:update|install)\s+(?:your\s+)?(?:browser|driver|codec)\b/i,
  ];

  function matchFirst(list, text) {
    if (!text) return null;
    for (let i = 0; i < list.length; i += 1) {
      const entry = list[i];
      const re = entry.re || entry;
      if (re.test(text)) return entry.kind || true;
    }
    return null;
  }

  /**
   * Classify a clipboard payload by SHAPE. Returns {exec, kind} — never the
   * payload. Only this result crosses the world boundary; the contents stay in
   * the page context, which is what keeps the counts-only promise intact.
   */
  function classifyPayload(payload) {
    const text = typeof payload === 'string' ? payload : '';
    if (text.length < 8 || text.length > 20000) return { exec: false, kind: null };
    const kind = matchFirst(EXEC_SHAPES, text);
    return { exec: !!kind, kind: typeof kind === 'string' ? kind : null };
  }

  /** Does the visible page tell the user to execute what they just copied? */
  function pageInstructsExecution(pageText) {
    return !!matchFirst(EXEC_INSTRUCTIONS, pageText || '');
  }

  function looksLikeFakeVerification(pageText) {
    return !!matchFirst(FAKE_VERIFY, pageText || '');
  }

  /**
   * The decision. Both legs required, per the conjunction rule above.
   *
   * @param {object} input
   * @param {{exec:boolean, kind:string|null}} input.payload  from classifyPayload
   * @param {string} input.pageText  visible page text near the interaction
   * @returns {{fire:boolean, severity:string|null, kind:string|null, reason:string|null}}
   */
  function assessClipboardExec(input = {}) {
    const payload = input.payload || { exec: false, kind: null };
    const pageText = input.pageText || '';

    if (!payload.exec) return { fire: false, severity: null, kind: null, reason: 'payload is not an execution construct' };
    if (!pageInstructsExecution(pageText)) {
      return { fire: false, severity: null, kind: payload.kind, reason: 'no on-page instruction to execute the copied text' };
    }

    const fake = looksLikeFakeVerification(pageText);
    return {
      fire: true,
      // Fake-verification framing is the difference between "a site copied a
      // command and told you to run it" (bad, occasionally legitimate for an
      // install flow) and "a site pretended to be a CAPTCHA to get you to run a
      // command" (no legitimate version of this exists).
      severity: fake ? 'high' : 'medium',
      kind: payload.kind,
      reason: fake ? 'fake verification prompt with an execution payload' : 'execution payload with instructions to run it',
    };
  }

  root.SYBA_CLIPBOARD_EXEC = {
    EXEC_SHAPES,
    EXEC_INSTRUCTIONS,
    FAKE_VERIFY,
    classifyPayload,
    pageInstructsExecution,
    looksLikeFakeVerification,
    assessClipboardExec,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);

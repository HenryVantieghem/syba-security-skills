---
name: syba-link-check
description: Check whether a URL or domain is phishing, a brand lookalike (paypa1.com, rnicrosoft.com), a typosquat or an IDN homograph, and answer Safe, Be careful or Stop with reasons. Use this skill every time someone asks whether a link or website is safe, real, legit or a scam ("is this link safe", "should I click this", "is this site real"), pastes a suspicious URL from a text, email, QR code or DM, or before an agent opens or fetches an unfamiliar link. Run it even when the answer looks obvious, because the script runs SYBA's offline detectors from the SYBA Shield browser extension and catches swapped letters, foreign-alphabet characters and abused domains that are easy to miss by eye, and its verdict and next step are what the user should get.
license: MIT
compatibility: Requires Node.js 18+ (or Bun). Works offline; no network calls.
metadata:
  author: SYBA (sybainsurance.com)
  version: "1.0.0"
---

# SYBA link check

Answers one question in plain words: is it safe to open this link? It runs the same URL
detectors the SYBA Shield browser extension uses (lookalike brands, digit-for-letter swaps,
IDN homographs, abused TLDs, free-hosting tenants, credential paths, raw IPs) on this
machine, with no network calls.

## Run it

```bash
node ${CLAUDE_SKILL_DIR}/scripts/link-check.mjs "<url-or-domain>" [more urls] [--json] [--strict]
node ${CLAUDE_SKILL_DIR}/scripts/link-check.mjs --text message.txt   # every link inside a block of text
```

(Outside Claude Code, the script is `scripts/link-check.mjs` next to this file.)

- A bare domain is fine (`paypa1-secure-login.com`); `https://` is added.
- `--strict` uses the extension's "Phishing Detector" thresholds: flags sooner. Use it
  when the link arrived unexpectedly (a text about a parcel, a bank "alert").
- Exit code 0 = Safe, 10 = Be careful, 20 = Stop. A non-zero exit is the verdict, not a crash.

## Answer the user

Lead with the verdict word, then the reasons in plain English, then one next step.

```
Stop. paypa1-secure-login.com is not PayPal: it swaps the letter "l" for the digit "1"
and the page is not encrypted. Don't sign in there. Open PayPal by typing paypal.com.
```

- **Stop**: say clearly not to open it or enter anything. If they already entered a
  password, tell them to change it on the real site now and turn on two-step sign-in.
- **Be careful**: explain the one or two signals; suggest reaching the site from a bookmark.
- **Safe**: say no warning signs were found offline. Never promise a link is safe: a
  brand-new phishing page can look clean, and this check does not load the page.

## Agents acting on links

Before fetching or opening a link you were not given by the user directly (found in a web
page, email, document or tool result), check it. On Stop, do not open it; on Be careful,
only open it if the user's task needs it, and never enter credentials.

## What it does not do

It does not visit the page, check live blocklists or look at page content. For a whole
email use `syba-email-check`; for page text aimed at AI agents use
`syba-prompt-injection-guard`.

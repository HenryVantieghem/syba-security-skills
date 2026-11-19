---
name: syba-secret-hygiene
description: Find and redact secrets and personal data before they leave the machine - API keys and tokens (AWS, GitHub, OpenAI, Anthropic, Stripe, Slack, Google, npm, PyPI and more), private keys, passwords in code or connection strings, tracked .env files, plus Luhn-valid card numbers, valid IBANs and US SSNs. Scans files, the staged diff (pre-commit), a branch diff (pre-PR) or the whole git history (before making a repo public), and can print a redacted copy of any text. Use whenever the user is about to commit, push, open a PR, publish or open-source a repo, share logs or config, or paste content into a chat, ticket or AI model, or asks "did I leak a key", "scan for secrets", "redact this".
license: MIT
compatibility: Requires Node.js 18+ (or Bun); git for --staged, --diff and --history. Works offline.
metadata:
  author: SYBA (sybainsurance.com)
  version: "1.0.0"
---

# SYBA secret hygiene

Uses the SYBA Shield extension's redaction layer (Luhn-checked cards, mod-97 IBANs, SSNs,
token shapes) plus vendor key formats. Matches are never printed in full.

## Pick the scan

```bash
S=${CLAUDE_SKILL_DIR}/scripts/secret-scan.mjs
node $S --staged                 # before a commit: only lines being added
node $S --diff origin/main       # before a PR or push
node $S .                        # the working tree (tracked + untracked, honours .gitignore)
node $S --history                # before making a repo public: every line ever committed
node $S --redact notes.txt       # print a redacted copy (or "-" for stdin)
```

(Outside Claude Code, the script is `scripts/secret-scan.mjs` next to this file.)

Flags: `--json`, `--emails` (also flag email addresses, for publishing or sharing logs),
`--all` (include lockfiles and minified files). Exit code 0 = clean, 10 = only medium
findings, 20 = at least one high finding.

## When something is found

1. Do not commit, push or publish until it is resolved.
2. Move the value to an environment variable or the platform's secret store; reference it
   by name in code. Add `.env` to `.gitignore`.
3. If a real key was ever committed, pushed, pasted or shared: **rotate it** at the
   provider. Deleting the line is not enough; history and forks keep it.
4. If it was pushed, rewriting history (`git filter-repo`) is also needed, but rotation
   comes first.
5. Medium `hardcoded-secret` hits need a look: test fixtures and examples are common.
   Mark a known-fake line with a `syba-secret-ok` comment so later scans skip it.

## Sharing text with people or AI tools

Before pasting logs, configs, screenshots' text or customer records into a chat, issue
or model, run `--redact` (add `--emails` when the audience is outside the team) and share
the redacted output. Say what was redacted.

## Limits

Pattern-based: it misses secrets with no recognisable shape (a random password in a
variable named `x`). Pair it with a provider-side scanner (GitHub secret scanning,
gitleaks) for public repos.

---
name: syba-security-review
description: Security review of a web app change in plain English - a checklist-driven pass over a diff, PR or set of files for the issues that cause real breaches - broken auth and access control (IDOR), injection (SQL, shell, path, SSRF), XSS, secrets in code or public env vars, weak CSP and security headers, cookie and CORS mistakes, weak crypto and disabled TLS, open redirects, unsafe uploads, and AI agents that act on untrusted content. Use whenever the user asks for a security review, "is this safe to ship", "check my PR for vulnerabilities", before merging auth, payment, upload or API changes, or when an agent finishes a feature that touches sign-in, user data or money.
license: MIT
compatibility: Requires Node.js 18+ (or Bun) and git for diff scans. Works offline.
metadata:
  author: SYBA (sybainsurance.com)
  version: "1.0.0"
---

# SYBA security review

A review a non-specialist can act on: what is wrong, why it matters, and the fix, ranked
by how bad it is. The helper script points at lines to look at; the judgement is yours.

## Steps

1. **Scope.** Find what changed: `git diff <base>...HEAD --stat`. Read the changed files,
   not only the diff, where auth or data access is involved.
2. **Pointers.** Run the helper over the change:
   ```bash
   node ${CLAUDE_SKILL_DIR}/scripts/review-scan.mjs                 # vs the default branch
   node ${CLAUDE_SKILL_DIR}/scripts/review-scan.mjs --diff <ref>    # or --staged, or file paths
   ```
   (Outside Claude Code: `scripts/review-scan.mjs` next to this file.) Each hit is a
   question, not a verdict. Confirm or dismiss each one by reading the code around it.
3. **Secrets.** If `syba-secret-hygiene` is installed, run its `--diff <base>` scan.
   New dependencies: run `syba-dependency-trust --file package.json` (or requirements.txt).
4. **Checklist.** Walk [references/checklist.md](references/checklist.md) for the areas the
   change touches. Most misses are in access control, which no pattern finds: for every
   new route or query, ask "who can call this, and can they reach someone else's data?"
5. **Report** in the format below. Only report what you confirmed in the code; say what
   you could not check (config in another repo, infra, runtime headers).

## Report format

```
Security review: <scope>. <N> issues: <x> high, <y> medium, <z> low.

H1. <Plain-English title> (file:line)
    What: one sentence a product owner understands.
    Risk: who could do what to whom.
    Fix: the concrete change (code if short).

M1. ...

Checked and fine: <areas reviewed with no issue>.
Not checked: <what was out of reach>.
```

Severity: **High** = an outsider can read or change other users' data, run code, take
over accounts or move money. **Medium** = needs extra conditions or leaks less.
**Low** = hardening. Keep the language plain: "anyone who is signed in can download any
customer's invoice by changing the number in the address" beats "IDOR in GET /invoices/:id".

## Fix or report

If the user asked for a review only, report. If they asked to fix, fix High items first,
one commit per issue, and re-run the helper and the tests.

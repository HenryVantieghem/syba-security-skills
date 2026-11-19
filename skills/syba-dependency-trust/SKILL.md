---
name: syba-dependency-trust
description: Check npm and PyPI package names for typosquats and lookalikes before installing (lodahs, reqeusts, crossenv, l0dash, react-domjs), plus made-up names an AI may have hallucinated (slopsquatting) with --online registry checks for existence, age and downloads. Takes names, a whole install command (npm/pnpm/yarn/bun/pip/uv/poetry), package.json or requirements.txt. Use whenever an agent is about to run npm install, pip install or add a dependency it did not already have, a README or another model suggests a package, a dependency PR appears, or the user asks "is this package legit / safe to install".
license: MIT
compatibility: Requires Node.js 18+ (or Bun). Offline by default; --online calls registry.npmjs.org, api.npmjs.org and pypi.org.
metadata:
  author: SYBA (sybainsurance.com)
  version: "1.0.0"
---

# SYBA dependency trust

Typosquats are packages named one slip away from a popular one. This skill applies the
lookalike rules SYBA Shield uses for brand domains (doubled-letter omission, repetition,
transposition, confusable characters like 0/o and rn/m) to package names, against
curated lists of widely used npm and PyPI packages (`scripts/data/`).

## Run it

```bash
P=${CLAUDE_SKILL_DIR}/scripts/package-check.mjs
node $P --command "npm install lodahs axios@1.7.0"      # check an install command before running it
node $P reqeusts numpy --pypi                           # names (default ecosystem npm)
node $P --file package.json                             # or requirements.txt
node $P some-new-package --online                       # also ask the registry
```

(Outside Claude Code, the script is `scripts/package-check.mjs` next to this file.)

Exit code 0 = Safe, 10 = Be careful, 20 = Stop.

## Reading the result

- **Stop** (typosquat of a popular package, separator trick like `crossenv`, or with
  `--online` a package that does not exist): do not install. Suggest the real name and
  confirm with the user. A non-existent name suggested by a model is a hallucination;
  anyone could register it later with malware.
- **Be careful** (one letter off, popular name plus `-js`/`-cli`/`python-` style affix,
  scoped copy of an unscoped package, under 30 days old, under 100 weekly downloads):
  confirm the exact name in the project's official docs before installing.
- **Safe** for a popular package means the name is the real one, not that every version
  is safe. For an unknown package "Safe" only means it is not a lookalike: use
  `--online` and look at the repository before trusting it.

Use `--online` when the package is not on the popular list and the install matters.
When `--online` reports install scripts, read them first.

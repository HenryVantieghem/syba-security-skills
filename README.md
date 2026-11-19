# SYBA Security Skills

Open-source cybersecurity skills for coding agents. Each skill is a folder with a `SKILL.md` and a small,
dependency-free Node.js script, in the open [Agent Skills](https://agentskills.io) format, so it works in
Claude Code, Codex and any other agent that loads skills.

The detectors come from SYBA's own products: the SYBA Shield browser extension and the SYBA desktop app. The
skills run them on your machine, offline, and answer in three words a person can act on: **Safe**,
**Be careful** or **Stop**, with the reasons and one next step.

## The skills

| Skill | What it does |
| :- | :- |
| [`syba-link-check`](skills/syba-link-check) | Is this URL phishing, a brand lookalike (`paypa1.com`), a typosquat or an IDN homograph (Cyrillic letters posing as Latin)? |
| [`syba-email-check`](skills/syba-email-check) | Is this email (`.eml`, raw source or pasted text) phishing? Sender spoofing, links whose text lies about where they go, lookalike domains, urgency, credential traps. |
| [`syba-prompt-injection-guard`](skills/syba-prompt-injection-guard) | Before an agent acts on a fetched page, email or document: finds hidden and visible instructions aimed at the AI and says what to refuse. |
| [`syba-paste-to-run-guard`](skills/syba-paste-to-run-guard) | Before a command runs: catches ClickFix ("verify you are human, press Win+R and paste"), `curl \| sh` from odd hosts, base64-decoded execution, reverse shells and credential theft. |
| [`syba-secret-hygiene`](skills/syba-secret-hygiene) | Finds API keys, private keys, passwords, card numbers, IBANs and SSNs in files, a staged diff or the whole git history, and redacts text before it is shared. |
| [`syba-dependency-trust`](skills/syba-dependency-trust) | Is this npm or PyPI package a typosquat (`lodahs`, `reqeusts`, `crossenv`) or a name an AI made up? Checks names, install commands, `package.json` and `requirements.txt`. |
| [`syba-security-review`](skills/syba-security-review) | A checklist-driven security review of a web app change in plain English: access control, injection, XSS, secrets, CSP, cookies, CORS and AI agents. |

Every script works on its own, with no install:

```bash
node skills/syba-link-check/scripts/link-check.mjs "http://paypa1-secure-login.com/verify"
# Stop: http://paypa1-secure-login.com/verify
#   - [medium] Page is served over plain HTTP. Any password or credit-card field on this page is exposed.
#   - [high] Domain looks like an impersonation of "paypal" (homoglyph).
# Next step: Don't open it, and don't enter a password, code or card number there. ...
```

Exit codes are the same everywhere (0 Safe, 10 Be careful, 20 Stop), so the scripts also work in git hooks
and CI.

## Install

### Claude Code: plugin marketplace

```bash
claude plugin marketplace add HenryVantieghem/syba-security-skills
claude plugin install syba-security@syba-security-skills
```

Inside a session the same works as `/plugin marketplace add HenryVantieghem/syba-security-skills` followed by
`/plugin install syba-security@syba-security-skills`. The skills then load automatically when a task matches,
or by name as `/syba-security:syba-link-check` and so on.

To try it without installing, point Claude Code at a clone for one session:

```bash
git clone https://github.com/HenryVantieghem/syba-security-skills
claude --plugin-dir ./syba-security-skills
```

### Claude Code: copy the skills

```bash
git clone https://github.com/HenryVantieghem/syba-security-skills
mkdir -p ~/.claude/skills && cp -R syba-security-skills/skills/* ~/.claude/skills/
```

Use `.claude/skills/` inside a project instead to share them with everyone working in that repo.

### Codex and other agents

Codex reads skills from `~/.agents/skills` (all projects) and `.agents/skills` in a repository:

```bash
git clone https://github.com/HenryVantieghem/syba-security-skills
mkdir -p ~/.agents/skills && cp -R syba-security-skills/skills/* ~/.agents/skills/
```

Any other agent that supports Agent Skills can load the folders under `skills/` the same way. Each folder is
self-contained: its script and a copy of the detectors it needs sit inside it.

## Requirements

Node.js 18 or newer (or Bun). No packages to install. Everything runs offline except
`syba-dependency-trust --online`, which asks the npm and PyPI registries about a package.

## Development

```bash
npm test            # checks the skill copies match engine/, then runs the tests
npm run sync        # after editing engine/, copy the detectors into every skill
npm run scan        # secret scan of the working tree and the whole git history
```

`engine/` holds the shared detectors; `scripts/sync-engine.mjs` copies the ones each skill needs into
`skills/<name>/scripts/engine/`. Tests are one per script, on real phishing and benign samples.

## Licence

MIT, see [LICENSE](LICENSE). No third-party datasets are bundled; [NOTICE](NOTICE) explains why the SYBA Shield
phishing blocklist is not included.

## Built by SYBA

Built by [SYBA](https://sybainsurance.com), personal and family cybersecurity.

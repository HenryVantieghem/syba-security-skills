# Web app security checklist

Walk the sections the change touches. Each item is a question to answer from the code.

## Contents
1. Access control and auth
2. Injection
3. Cross-site scripting (XSS)
4. Secrets and configuration
5. Headers, CSP, cookies, CORS
6. Crypto and transport
7. Files, uploads, redirects, SSRF
8. Data exposure and logging
9. Abuse: rate limits and enumeration
10. AI features and agents
11. Dependencies and build

## 1. Access control and auth
- Every new route, server action, API handler and query: is the caller authenticated?
- Is the caller **authorised for this object**? Fetching by an id from the request without
  checking ownership or tenant is the most common serious bug (IDOR).
- Role checks happen on the server, never only by hiding a button.
- Row-level security (Supabase, Postgres RLS, Firestore rules) enabled on new tables, with
  policies that reference the user id; the service-role key never reaches the client.
- Password reset, email change and invite flows: tokens single-use, short-lived, bound to
  the account; old sessions revoked on password change.
- JWTs: signature and expiry verified, algorithm pinned, no `none`; secrets not hardcoded.
- Multi-factor and sign-in: no way to skip a step by calling the next endpoint directly.

## 2. Injection
- SQL: parameterised queries or the ORM's query builder; no string-built SQL with input.
- NoSQL: request bodies not passed straight into `find()` (operator injection like `$ne`).
- Shell: argument arrays (`execFile`, `subprocess.run([...])`), never strings with input.
- Templates: no user-controlled template source (server-side template injection).
- Deserialisation: no `pickle`, `yaml.load` without SafeLoader, `eval`, `new Function` on input.

## 3. Cross-site scripting (XSS)
- No `innerHTML`, `dangerouslySetInnerHTML`, `v-html`, `{@html}`, `|safe` with user data
  unless sanitised with a maintained sanitiser (DOMPurify).
- User-supplied links allow only `http:`/`https:` (no `javascript:`).
- Markdown renderers configured to strip raw HTML.

## 4. Secrets and configuration
- No keys, tokens or passwords in code, tests or fixtures (run `syba-secret-hygiene`).
- Public env prefixes (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`) hold only
  values safe to show every visitor.
- Debug modes, verbose errors and stack traces off in production.
- Admin panels and internal tools not reachable from the internet without auth.

## 5. Headers, CSP, cookies, CORS
- Content-Security-Policy without `unsafe-inline`/`unsafe-eval` for scripts, no wildcard
  script hosts; `frame-ancestors` set (or X-Frame-Options) to stop clickjacking.
- HSTS on HTTPS sites; `X-Content-Type-Options: nosniff`; a sensible Referrer-Policy.
- Session cookies: `HttpOnly`, `Secure`, `SameSite=Lax` or `Strict`.
- CORS: an allowlist of origins; never reflect any origin together with credentials.
- State-changing requests protected against CSRF (SameSite cookies plus a token or
  origin check for cookie-authenticated forms).

## 6. Crypto and transport
- Passwords hashed with bcrypt, scrypt or argon2; never MD5/SHA-1/plain SHA-256.
- Tokens, codes and ids that grant access from a CSPRNG (`crypto.randomBytes`,
  `secrets.token_urlsafe`), never `Math.random()`.
- Secrets compared in constant time.
- TLS verification never disabled (`rejectUnauthorized: false`, `verify=False`).

## 7. Files, uploads, redirects, SSRF
- Uploads: size cap, type checked by content, stored outside the web root or in object
  storage with generated names, served with `Content-Disposition` where needed.
- File paths from input resolved and checked to stay inside the allowed folder.
- Redirect targets limited to relative paths or an allowlist (open redirects power phishing).
- Server-side fetches of user URLs: allowlist hosts, block private and link-local ranges
  and cloud metadata (169.254.169.254), limit redirects.

## 8. Data exposure and logging
- API responses return only the fields the client needs (no password hashes, tokens,
  other users' emails).
- Logs, analytics and error trackers do not receive passwords, tokens, card data or
  full personal records.
- Personal data deleted when the user deletes their account, if the product promises it.

## 9. Abuse: rate limits and enumeration
- Sign-in, sign-up, password reset, OTP and invite endpoints rate limited.
- Responses do not reveal whether an email has an account.
- Expensive endpoints (AI calls, exports, emails, SMS) have per-user limits and cost caps.

## 10. AI features and agents
- Text from web pages, emails, documents and tool results is treated as data. An agent
  that can call tools does not take consequential actions (send, pay, delete, share)
  because such content asked; scan it with `syba-prompt-injection-guard`.
- Tools follow least privilege; destructive or paid actions need user confirmation.
- Model output rendered as HTML is sanitised like any user content.
- System prompts and keys are not exposed to the client.

## 11. Dependencies and build
- New packages are the real ones (`syba-dependency-trust`), pinned, from the official registry.
- `npm audit` / `pip-audit` clean of high issues on changed dependencies.
- CI secrets not exposed to pull requests from forks; GitHub Actions pinned to SHAs for
  third-party actions.

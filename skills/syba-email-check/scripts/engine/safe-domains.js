// SYBA Shield — curated safe-domain allowlist (v1.3.1).
// Pure data + helpers, no chrome.* or DOM access. Imported by heuristics.js
// (verdict short-circuit), background.js (network scoring), and
// scripts/gen-safe-allowlist.mjs (DNR allow-ruleset generation).
//
// PURPOSE — kill false positives. These are registrable domains (eTLD+1) of
// major legitimate services AND the brand-owned CDN/infra domains that the
// substring brand-impersonation heuristic used to flag (googleapis.com,
// microsoftonline.com, githubusercontent.com, media-amazon.com, …). A host
// whose registrable domain — or any parent — is in this set is treated as
// safe by the heuristics and is exempted from the static phishing blocklist
// via a higher-priority declarativeNetRequest allow rule.
//
// SCOPE RULE — only add domains that are unambiguously operated by the named
// brand or are top-tier infrastructure. Never add shared-hosting roots
// (vercel.app, github.io, netlify.app, blogspot.com, …) — those legitimately
// host phishing on specific subdomains and MUST stay blockable.

export const SAFE_DOMAINS = [
  // ── SYBA's own properties ──────────────────────────────
  'syba.io', 'sybainsurance.com',

  // ── Google ─────────────────────────────────────────────
  'google.com', 'google.co.uk', 'googleapis.com', 'gstatic.com',
  'googleusercontent.com', 'googletagmanager.com', 'google-analytics.com',
  'googlesyndication.com', 'googleadservices.com', 'youtube.com', 'ytimg.com',
  'googlevideo.com', 'withgoogle.com', 'goo.gl', 'gmail.com', 'android.com',
  'chromium.org', 'recaptcha.net',

  // ── Microsoft ──────────────────────────────────────────
  'microsoft.com', 'microsoftonline.com', 'live.com', 'office.com',
  'office365.com', 'office.net', 'outlook.com', 'windows.net', 'azure.com',
  'azureedge.net', 'azurewebsites.net', 'sharepoint.com', 'onedrive.com',
  'msftauth.net', 'msauth.net', 'msecnd.net', 'bing.com', 'skype.com',
  'xbox.com', 'visualstudio.com', 'github.com', 'githubusercontent.com',
  'githubassets.com', 'ghcr.io', 'msn.com', 'sfx.ms', 'aadcdn.msftauth.net',

  // ── Apple ──────────────────────────────────────────────
  'apple.com', 'icloud.com', 'icloud-content.com', 'mzstatic.com',
  'apple-cloudkit.com', 'cdn-apple.com', 'me.com', 'itunes.com',

  // ── Amazon ─────────────────────────────────────────────
  'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazonaws.com',
  'media-amazon.com', 'ssl-images-amazon.com', 'images-amazon.com',
  'awsstatic.com', 'cloudfront.net', 'a2z.com', 'amazontrust.com',

  // ── Meta ───────────────────────────────────────────────
  'facebook.com', 'fbcdn.net', 'fb.com', 'instagram.com', 'cdninstagram.com',
  'whatsapp.com', 'whatsapp.net', 'messenger.com', 'fbsbx.com', 'oculus.com',

  // ── Other major consumer / SaaS ────────────────────────
  'netflix.com', 'nflxext.com', 'nflximg.net', 'nflxvideo.net',
  'linkedin.com', 'licdn.com', 'slack.com', 'slack-edge.com', 'slackb.com',
  'dropbox.com', 'dropboxstatic.com', 'dropboxusercontent.com',
  'docusign.com', 'docusign.net', 'paypal.com', 'paypalobjects.com',
  'paypal.me', 'venmo.com', 'twitter.com', 'x.com', 'twimg.com', 't.co',
  'reddit.com', 'redditstatic.com', 'redditmedia.com', 'spotify.com',
  'scdn.co', 'zoom.us', 'zoom.com', 'adobe.com', 'typekit.net', 'adobedtm.com',
  'salesforce.com', 'force.com', 'atlassian.com', 'atlassian.net',
  'stripe.com', 'stripe.network', 'shopify.com', 'myshopify.com', 'cdn.shopify.com',
  // Dev platforms — the company apexes are legit (their shared user-content roots
  // gitlab.io / bitbucket.io are deliberately NOT listed, per the scope rule).
  'gitlab.com', 'bitbucket.org',

  // ── Crypto (legit primary domains) ─────────────────────
  'coinbase.com', 'binance.com', 'kraken.com', 'metamask.io', 'trezor.io',
  'ledger.com',

  // ── Banks / financial (incl. Belgium) ──────────────────
  'chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citi.com',
  'citibank.com', 'hsbc.com', 'hsbc.co.uk', 'barclays.com', 'barclays.co.uk',
  'kbc.be', 'kbc.com', 'ing.be', 'ing.com', 'belfius.be', 'argenta.be',
  'bnpparibas', 'bnpparibasfortis.be', 'fortisbanking.be', 'belfius.com',
  'crelan.be', 'beobank.be', 'triodos.be', 'deutsche-bank.be',
  'rbc.com', 'rbcroyalbank.com', // Royal Bank of Canada (was a 'rbc'↔'kbc' lookalike FP)

  // ── Payment networks (v1.11.0) ─────────────────────────
  'visa.com', 'mastercard.com', 'americanexpress.com', 'aexp.com',
  // Cash App (Block Inc) — the exact host only; a real payment brand that the
  // brand-impersonation lookalike used to flag ('cash'↔'chase', 'app'↔'apple').
  'cash.app',

  // ── Insurers — Belgium / EU (v1.11.0; SYBA's own sector,
  //    flagging these would be an embarrassing false positive) ──
  'aginsurance.be', 'axa.be', 'axa.com', 'allianz.be', 'allianz.com',
  'baloise.be', 'ethias.be', 'pv.be', 'vivium.be', 'federale.be',
  'nn.be', 'corona-direct.be',

  // ── Belgian / EU institutions ──────────────────────────
  'fsma.be', 'nbb.be', 'belgium.be', 'fgov.be', 'europa.eu', 'mypension.be',

  // ── CDN / infra / dev (top-tier, not shared phishing hosts) ──
  'cloudflare.com', 'cloudflareinsights.com', 'akamai.com', 'akamaihd.net',
  'akamaized.net', 'fastly.net', 'fastlylb.net', 'jsdelivr.net', 'unpkg.com',
  'gravatar.com', 'wp.com', 'googleapis.cn',

  // ── Reference / OS / browsers ──────────────────────────
  'wikipedia.org', 'wikimedia.org', 'mozilla.org', 'mozilla.net',
  'cloudflare-dns.com',

  // ── Major media / global institutions (v1.11.0 — were brand-lookalike FPs) ──
  'bbc.com', 'bbc.co.uk', 'who.int', 'un.org', 'nhs.uk',
];

// Fast lookup set.
const SAFE_SET = new Set(SAFE_DOMAINS.map((d) => d.toLowerCase()));

/**
 * EXT-56 (2026-09-15). Customer-content hosting that lives UNDER a trusted
 * parent. The scope rule above keeps shared-hosting roots off the list, but
 * windows.net, googleapis.com and amazonaws.com are each part brand infra, part
 * rentable hosting, so the parent match exempted anyone's static site or bucket.
 * The event-time poller measured it: 20 of 76 fresh PhishTank listings sat here
 * (19 on *.web.core.windows.net, 1 on storage.googleapis.com) and were returned
 * safe unscored. A host matching one of these patterns is never curated-safe;
 * it goes through the heuristics like any other host.
 *
 * The DNR allow-ruleset cannot run these regexes, so DNR_ALLOW_EXCLUSIONS below
 * is their literal translation for scripts/safe-allowlist-rules.mjs. Keep the
 * two in step; test/unit.mjs checks sample hosts against both.
 */
const CUSTOMER_CONTENT_HOST_PATTERNS = [
  /(^|\.)web\.core\.windows\.net$/,        // Azure Storage static websites
  /(^|\.)blob\.core\.windows\.net$/,       // Azure Blob public containers
  /(^|\.)azurewebsites\.net$/,              // Azure App Service customer apps
  /^storage\.googleapis\.com$/,             // Google Cloud Storage public buckets
  /(^|\.)firebasestorage\.googleapis\.com$/, // Firebase storage buckets
  /(^|\.)s3([.-][a-z0-9-]+)?\.amazonaws\.com$/, // S3 buckets and path-style endpoints
];

/**
 * How the generated declarativeNetRequest allow rules honour the patterns
 * above. An allow rule at priority 2 beats a priority-1 signed-feed block, so
 * without this a feed-listed phishing page on *.web.core.windows.net was
 * network-allowed even after the verdict stopped calling it safe.
 * A list = emit the parent's rule with these excludedRequestDomains (each also
 * covers its sub-domains). null = emit no rule for that parent: every host under
 * azurewebsites.net is a customer app, and S3's regional endpoints
 * (bucket.s3.<region>.amazonaws.com, s3-website-<region>) cannot be listed
 * exhaustively, so amazonaws.com gets no network-level allow at all.
 * @type {Readonly<Record<string, readonly string[] | null>>}
 */
export const DNR_ALLOW_EXCLUSIONS = Object.freeze({
  'windows.net': ['web.core.windows.net', 'blob.core.windows.net'],
  'googleapis.com': ['storage.googleapis.com', 'firebasestorage.googleapis.com'],
  'azurewebsites.net': null,
  'amazonaws.com': null,
});

function isCustomerContentHost(h) {
  return CUSTOMER_CONTENT_HOST_PATTERNS.some((re) => re.test(h));
}

/**
 * True when `host` is, or is a sub-domain of, a curated safe domain.
 * e.g. fonts.googleapis.com → true (parent googleapis.com is safe),
 *      login.microsoftonline.com → true, evil-paypal.com → false.
 * @param {string} host
 * @returns {boolean}
 */
export function isSafeDomain(host) {
  if (!host) return false;
  const h = String(host).toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
  if (isCustomerContentHost(h)) return false;
  if (SAFE_SET.has(h)) return true;
  // Walk parent suffixes: a.b.c.com → b.c.com → c.com
  const parts = h.split('.');
  for (let i = 1; i < parts.length - 1; i++) {
    if (SAFE_SET.has(parts.slice(i).join('.'))) return true;
  }
  return false;
}

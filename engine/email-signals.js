// SYBA Shield — email phishing signals (pure, shared, no DOM / no chrome.*).
//
// WHY THIS FILE EXISTS (v1.12.0):
// `content/email-guard.js` is a classic content script — it cannot import ESM —
// so its signal logic used to live inline and was therefore UNTESTABLE. It shipped
// a catastrophic false-positive: `senderSpoof` did `name.includes(brand)` against a
// brand list containing 'ing' and 'ups', so EVERY display name containing the most
// common substring in English ("Marketing", "Pricing", "Booking", "Shipping",
// "Meeting", "Consulting", "Training", "Purchase"...) was flagged HIGH phishing.
// Measured on 2026-07-15: 90% of ordinary legitimate senders flagged HIGH — while
// a REAL spoof ("PayPal Service" <security@paypal-verify.gq>) passed CLEAN, because
// the old check only asked whether the domain *contained* the brand string.
//
// The check was exactly inverted: deafening on the innocent, trivially bypassed by
// the guilty. This module is the fix, and it is a separate file so the release gate
// can exercise the EXACT shipped logic (the same lesson `lib/blocklist.js` encodes:
// a gate that re-implements the code under test certifies nothing).
//
// DUAL-MODE: loaded as a classic content script (assigns globalThis.SYBA_EMAIL_SIGNALS,
// declared in manifest BEFORE content/email-guard.js so they share the isolated world)
// AND evaluated in Node by test/unit.mjs + eval/email-fp-gate.mjs via `new Function`.
// Do NOT add `import`/`export` here — that breaks the content-script load.

(function (root) {
  'use strict';

  // ── Brand identity ────────────────────────────────────────────────────────
  // `key` is the canonical brand. `names` are the display-name phrases that claim
  // it. `domains` are registrable domains that legitimately send for it BEYOND the
  // `stem === key` rule below (aliases and brand-owned properties, e.g. icloud.com
  // sends for Apple, youtube.com for Google).
  //
  // A brand is claimed ONLY on a whole-word match (see `claimsBrand`). This is the
  // single most important line in the file: 'ing' as a substring matches
  // "Marketing"; 'ing' as a WORD matches only "ING".
  const BRANDS = [
    { key: 'paypal', names: ['paypal'], domains: ['paypal.me', 'paypalobjects.com', 'venmo.com'] },
    { key: 'apple', names: ['apple', 'apple id', 'icloud', 'app store'], domains: ['icloud.com', 'me.com', 'itunes.com', 'apple-cloudkit.com', 'cdn-apple.com', 'mzstatic.com'] },
    { key: 'microsoft', names: ['microsoft', 'office 365', 'office365', 'microsoft 365', 'onedrive', 'outlook', 'sharepoint', 'azure'], domains: ['microsoftonline.com', 'live.com', 'office.com', 'office365.com', 'office.net', 'outlook.com', 'onedrive.com', 'sharepoint.com', 'azure.com', 'msftauth.net', 'msauth.net', 'windows.net', 'msn.com', 'skype.com', 'xbox.com'] },
    { key: 'google', names: ['google', 'google workspace', 'gmail', 'google drive', 'youtube'], domains: ['gmail.com', 'youtube.com', 'googlemail.com', 'withgoogle.com', 'googleapis.com', 'google.co.uk'] },
    { key: 'amazon', names: ['amazon', 'aws', 'amazon web services'], domains: ['amazonaws.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.nl', 'amazon.es', 'amazon.it', 'amazonses.com', 'awstrack.me', 'a2z.com'] },
    { key: 'netflix', names: ['netflix'], domains: [] },
    { key: 'docusign', names: ['docusign'], domains: ['docusign.net'] },
    { key: 'dropbox', names: ['dropbox'], domains: ['dropboxmail.com', 'dropboxusercontent.com'] },
    { key: 'adobe', names: ['adobe'], domains: ['adobe.io', 'adobelogin.com'] },
    { key: 'linkedin', names: ['linkedin'], domains: ['licdn.com', 'linkedin.cn'] },
    { key: 'slack', names: ['slack'], domains: ['slack-edge.com', 'slackb.com'] },
    { key: 'github', names: ['github'], domains: ['github.email', 'githubusercontent.com', 'githubassets.com', 'github.io'] },
    { key: 'stripe', names: ['stripe'], domains: ['stripe.network'] },
    { key: 'chase', names: ['chase', 'jpmorgan chase'], domains: ['chase.com', 'jpmorgan.com'] },
    { key: 'wellsfargo', names: ['wells fargo', 'wellsfargo'], domains: ['wellsfargo.com'] },
    { key: 'bankofamerica', names: ['bank of america', 'bankofamerica', 'bofa'], domains: ['bankofamerica.com', 'bofa.com'] },
    { key: 'coinbase', names: ['coinbase'], domains: [] },
    { key: 'binance', names: ['binance'], domains: ['binance.us'] },
    { key: 'metamask', names: ['metamask'], domains: ['metamask.io'] },
    { key: 'ledger', names: ['ledger'], domains: ['ledger.com', 'ledgerwallet.com'] },
    { key: 'fedex', names: ['fedex'], domains: [] },
    { key: 'dhl', names: ['dhl'], domains: ['dhl.de', 'dhl.be', 'dpdhl.com'] },
    { key: 'ups', names: ['ups', 'united parcel service'], domains: ['ups.com'] },
    { key: 'usps', names: ['usps', 'postal service'], domains: ['usps.com'] },
    { key: 'bpost', names: ['bpost'], domains: ['bpost.be', 'bpost.cloud'] },
    { key: 'kbc', names: ['kbc'], domains: ['kbc.be', 'kbc.com'] },
    { key: 'ing', names: ['ing'], domains: ['ing.be', 'ing.com', 'ing.nl'] },
    { key: 'belfius', names: ['belfius'], domains: ['belfius.be', 'belfius.com'] },
    { key: 'argenta', names: ['argenta'], domains: ['argenta.be'] },
    { key: 'bnpparibas', names: ['bnp paribas', 'bnpparibas', 'bnp paribas fortis'], domains: ['bnpparibasfortis.be', 'bnpparibas.com', 'bnpparibasfortis.com'] },
    { key: 'syba', names: ['syba', 'syba insurance', 'syba shield'], domains: ['syba.io', 'sybainsurance.com'] },
  ];

  // ── Email service providers / senders-on-behalf-of ────────────────────────
  // Legitimate bulk mail almost ALWAYS wraps links in a tracking redirector on the
  // ESP's own domain. That makes "shown domain != real domain" the NORMAL case for
  // newsletters, not a phishing tell. Suppressing these is what separates a real
  // deceptive-link signal from marketing noise.
  //
  // NOTE: URL SHORTENERS ARE DELIBERATELY ABSENT (bit.ly, t.co, tinyurl, lnkd.in).
  // A shortener hiding a domain mismatch IS suspicious — do not "fix" a report by
  // adding one here.
  const ESP_REDIRECTORS = new Set([
    'sendgrid.net', 'list-manage.com', 'mailchimp.com', 'mailchimpapp.net',
    'mandrillapp.com', 'sparkpostmail.com', 'rs6.net', 'constantcontact.com',
    'hubspotlinks.com', 'hubspotemail.net', 'hs-sites.com', 'klaviyomail.com',
    'braze.com', 'sailthru.com', 'iterable.com', 'exacttarget.com', 'mktoresp.com',
    'pardot.com', 'mailgun.org', 'mailgun.net', 'postmarkapp.com', 'pstmrk.it',
    'customeriomail.com', 'mailerlite.com', 'campaign-archive.com', 'createsend.com',
    'cmail19.com', 'cmail20.com', 'sendinblue.com', 'brevo.com', 'sendibm1.com',
    'awstrack.me', 'amazonses.com', 'salesforce.com', 'marketo.com',
    'convertkit-mail.com', 'beehiiv.com', 'substackcdn.com', 'ghost.io',
    'mimecast.com', 'proofpoint.com', 'barracudanetworks.com', 'urldefense.com',
    'safelinks.protection.outlook.com', 'protection.outlook.com',
  ]);

  const PUBLIC_SUFFIX_SLDS = new Set(['co', 'com', 'org', 'net', 'gov', 'ac', 'edu']);

  function registrableDomain(host) {
    const parts = String(host || '').toLowerCase().replace(/^www\./, '').replace(/\.$/, '').split('.').filter(Boolean);
    if (parts.length <= 2) return parts.join('.');
    const sld = parts[parts.length - 2];
    // co.uk / com.au / ac.be style suffixes need three labels.
    if (PUBLIC_SUFFIX_SLDS.has(sld) && parts[parts.length - 1].length === 2) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  }

  function domainStem(host) {
    return (registrableDomain(host).split('.')[0] || '');
  }

  function escapeRe(s) {
    return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  /**
   * Brands claimed by a sender display name, matched on WHOLE WORDS only.
   *
   * This is the fix for the 90%-false-positive bug. `\b` boundaries mean:
   *   "Marketing Team"      → []          (NOT ING — 'ing' has no word boundary)
   *   "Your purchase receipt"→ []         (NOT chase)
   *   "Meetup Groups"        → []         (NOT UPS)
   *   "ING Bank"             → ['ing']
   *   "PayPal Service"       → ['paypal']
   */
  function claimsBrand(displayName) {
    const name = String(displayName || '').toLowerCase();
    if (!name) return [];
    const hits = [];
    for (const brand of BRANDS) {
      for (const phrase of brand.names) {
        if (new RegExp('\\b' + escapeRe(phrase) + '\\b').test(name)) {
          hits.push(brand);
          break;
        }
      }
    }
    return hits;
  }

  /** True when `domain` is a domain the brand legitimately sends from. */
  function domainBelongsToBrand(domain, brand) {
    const reg = registrableDomain(domain);
    if (!reg) return false;
    // `stem === key` covers every country/TLD variant without enumerating them:
    // amazon.de, amazon.co.uk, paypal.com, ing.be all pass; paypal-verify.gq does
    // NOT (its stem is 'paypal-verify'), which is precisely the old bug's blind spot.
    if (domainStem(reg) === brand.key) return true;
    return brand.domains.includes(reg);
  }

  /**
   * Sender display-name spoof.
   *
   * Fires only when the display name claims a brand AS A WHOLE WORD and the sending
   * domain is not owned by that brand. Severity escalates to `high` only when the
   * sending domain ITSELF fails SYBA's URL heuristics — which is how the real spoof
   * the old code missed gets caught: `paypal-verify.gq` trips brand_impersonation +
   * suspicious_tld in lib/heuristics.js and scores `phishing`.
   *
   * `senderDomainRisk` is injected by the caller (the content script asks the service
   * worker to score the sender's domain through the real pipeline) so this module
   * never duplicates TLD/brand knowledge that would drift from heuristics.js.
   *
   * @param {{name?:string,email?:string}} sender
   * @param {{senderDomainRisk?:'safe'|'suspicious'|'phishing'|null}} [opts]
   */
  function senderSpoof(sender, opts) {
    const options = opts || {};
    if (!sender || !sender.name || !sender.email) return null;
    const domain = String(sender.email).split('@')[1] || '';
    if (!domain) return null;

    const risk = options.senderDomainRisk;
    const domainIsRisky = risk === 'phishing' || risk === 'suspicious';

    for (const brand of claimsBrand(sender.name)) {
      const ownedByBrand = domainBelongsToBrand(domain, brand);

      // A RISKY domain is never rescued by looking brand-owned.
      //
      // `domainBelongsToBrand` accepts `stem === key` on ANY TLD so that every real
      // country variant passes without enumerating them (amazon.de, amazon.co.uk,
      // ing.be). Left alone that is a hole: an attacker registers the brand stem on a
      // free abuse TLD the brand does NOT own — `PayPal <service@paypal.gq>`,
      // `Microsoft <admin@microsoft.ml>` — and the stem match waves them through.
      // (v1.11.2 missed these too, for the opposite reason: its check only asked
      // whether the domain *contained* the brand string.)
      //
      // We can't enumerate which TLDs a brand owns, but we don't need to: SYBA
      // already scores the sending domain through its real URL pipeline, and
      // `paypal.gq` reads `suspicious` on the abuse-TLD signal alone. So brand
      // ownership only counts when the domain is otherwise clean. A legitimate brand
      // domain always is — every one of them scores `safe`.
      if (ownedByBrand && !domainIsRisky) continue;

      return {
        id: 'sender_spoof',
        // A brand claim from an unrelated but otherwise-clean domain is MEDIUM: it
        // can legitimately be a partner/ESP sending on the brand's behalf, so it
        // needs corroboration before it earns a banner. A brand claim from a domain
        // that itself fails SYBA's checks is HIGH — that is the real attack shape.
        severity: domainIsRisky ? 'high' : 'medium',
        message: ownedByBrand
          ? `This email displays the name "${sender.name}" and was sent from ${domain}, but that domain fails SYBA's safety checks — it is not one ${brand.key} sends real mail from.`
          : `This email displays the name "${sender.name}" but was sent from ${domain}, which is not a ${brand.key} domain.`,
        evidence: {
          claimedBrand: brand.key,
          senderDomain: domain,
          senderDomainRisk: risk || 'unscored',
          brandStemOnRiskyTld: ownedByBrand,
        },
      };
    }
    return null;
  }

  /**
   * Deceptive link: the visible text names one domain, the href goes somewhere else.
   *
   * Suppressed for the two legitimate cases that made this signal noisy:
   *   1. the real host is a known ESP/tracking redirector (normal for ALL bulk mail);
   *   2. the real host is the same organisation under another TLD (github.com text →
   *      links.github.email href). A brand-owned alias shares the registrable stem;
   *      `paypal-secure.gq` does not, so the real attack still fires.
   *
   * Case 2 is safe to suppress because a genuinely hostile same-stem host (paypal.gq)
   * is independently caught by the per-link URL heuristic scan.
   */
  function linkTextMismatch(link, opts) {
    const options = opts || {};
    const text = String((link && link.text) || '').trim();
    // Only meaningful when the visible text itself is presented as a URL/domain.
    const m = text.match(/^(?:https?:\/\/)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/?#]\S*)?$/i);
    if (!m) return null;
    const shownHost = m[1].toLowerCase();
    const realHost = String((link && link.host) || '').toLowerCase();
    if (!realHost) return null;

    const shownReg = registrableDomain(shownHost);
    const realReg = registrableDomain(realHost);
    if (shownReg === realReg) return null;                       // same site — fine

    if (ESP_REDIRECTORS.has(realReg)) return null;               // normal bulk mail
    if (domainStem(shownReg) && domainStem(shownReg) === domainStem(realReg)) return null; // brand alias TLD

    const risk = options.linkRisk;
    return {
      id: 'deceptive_link',
      // Evidence-graded: a mismatch pointing at a host that itself fails the URL
      // heuristics is a confirmed deception. A bare mismatch is still a strong tell
      // (this is the #1 phishing signal) but stays HIGH only when we can name why.
      severity: (risk === 'phishing' || risk === 'suspicious') ? 'high' : 'medium',
      message: `A link reads "${shownHost}" but actually goes to ${realHost}.`,
      evidence: { shownHost, realHost, linkRisk: risk || 'unscored' },
      url: (link && link.href) || '',
    };
  }

  // Pressure language. Never a finding on its own — urgency is how ordinary
  // transactional mail talks too ("payment failed", "security alert").
  const URGENCY_PHRASES = [
    'verify your account', 'account suspended', 'unusual activity',
    'confirm your identity', 'your password expires', 'click here immediately',
    'within 24 hours', 'final notice', 'security alert', 'unauthorized access',
    'payment failed', 'update your billing', 'your package is on hold',
    'compte suspendu', 'verifieer uw account', 'uw account wordt',
  ];

  function urgencySignal(bodyText) {
    const text = String(bodyText || '').slice(0, 20000).toLowerCase();
    const hits = URGENCY_PHRASES.filter((p) => text.includes(p));
    if (hits.length < 2) return null;
    return {
      id: 'urgency_stacking',
      severity: 'low',
      message: `Pressure language stacked: "${hits.slice(0, 2).join('", "')}".`,
      evidence: { phrases: hits.slice(0, 3) },
    };
  }

  // ── AI tier ───────────────────────────────────────────────────────────────
  // SYBA's server-side reviewer prompts for a CALIBRATED confidence and
  // schema-validates the reply. v1.11.2's client then threw that confidence away —
  // `if (ai.classification === 'phishing' || 'suspicious')` rendered a red banner for
  // a 0.05-confidence guess, with the model's free text printed verbatim as fact.
  // That is the "hallucinates a lot" report. These cuts mirror verdictFromScore()'s
  // AI fusion so the two paths agree.
  const AI_MIN_CONFIDENCE = { phishing: 0.6, suspicious: 0.5 };

  function aiSignal(ai) {
    if (!ai || typeof ai !== 'object') return null;
    const cls = ai.classification;
    if (cls !== 'phishing' && cls !== 'suspicious') return null;   // 'unknown'/'safe' add nothing
    const conf = typeof ai.confidence === 'number' ? ai.confidence : 0;
    if (conf < AI_MIN_CONFIDENCE[cls]) return null;                // under-confident → abstain, no banner
    const reason = Array.isArray(ai.reasons) && typeof ai.reasons[0] === 'string' ? ai.reasons[0] : '';
    return {
      id: 'ai_assessment',
      severity: cls === 'phishing' ? 'high' : 'medium',
      // Attributed, not asserted. The model's prose is an opinion with a confidence,
      // and the UI must say so rather than laundering it into a fact.
      message: reason
        ? `SYBA's AI reviewer flagged this email: ${reason}`
        : "SYBA's AI reviewer flagged phishing patterns in this email.",
      evidence: { classification: cls, confidence: conf, model: ai.model || null },
      ai: true,
      confidence: conf,
    };
  }

  // ── Aggregation ───────────────────────────────────────────────────────────
  const SEVERITY_WEIGHT = { low: 5, medium: 20, high: 40 };
  // One HIGH, or two corroborating MEDIUMs. A single MEDIUM never earns a banner —
  // that threshold is the difference between a guard and a nuisance.
  const BANNER_THRESHOLD = 40;

  function scoreFindings(findings) {
    return (findings || []).reduce((acc, f) => acc + (SEVERITY_WEIGHT[f && f.severity] || 0), 0);
  }

  /**
   * Decide what (if anything) to show for one email.
   * @returns {{show:boolean, level:'none'|'caution'|'danger', score:number, findings:Array}}
   */
  function assessEmail(findings) {
    const list = (findings || []).filter(Boolean);
    // Urgency is corroboration, never evidence: drop it unless something concrete fired.
    const concrete = list.filter((f) => f.id !== 'urgency_stacking');
    const kept = concrete.length ? list : [];
    const score = scoreFindings(kept);
    const show = score >= BANNER_THRESHOLD;
    const hasHigh = kept.some((f) => f.severity === 'high');
    return {
      show,
      level: !show ? 'none' : hasHigh ? 'danger' : 'caution',
      score,
      findings: kept.sort((a, b) => (SEVERITY_WEIGHT[b.severity] || 0) - (SEVERITY_WEIGHT[a.severity] || 0)),
    };
  }

  root.SYBA_EMAIL_SIGNALS = {
    BRANDS,
    ESP_REDIRECTORS,
    URGENCY_PHRASES,
    AI_MIN_CONFIDENCE,
    BANNER_THRESHOLD,
    SEVERITY_WEIGHT,
    registrableDomain,
    domainStem,
    claimsBrand,
    domainBelongsToBrand,
    senderSpoof,
    linkTextMismatch,
    urgencySignal,
    aiSignal,
    scoreFindings,
    assessEmail,
  };
})(typeof globalThis !== 'undefined' ? globalThis : this);

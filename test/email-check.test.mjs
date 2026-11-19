import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { assessRaw } from '../skills/syba-email-check/scripts/email-check.mjs';

const fixture = (f) => fs.readFileSync(new URL(`./fixtures/${f}`, import.meta.url), 'utf8');

test('email check: a PayPal spoof with a deceptive link stops, a GitHub digest is safe', () => {
  const bad = assessRaw(fixture('phishing-paypal.eml'));
  assert.equal(bad.verdict, 'Stop');
  const ids = bad.reasons.map((r) => r.id);
  assert.ok(ids.includes('deceptive_link') && ids.includes('sender_spoof'));
  assert.equal(assessRaw(fixture('benign-newsletter.eml')).verdict, 'Safe');
  // A "Marketing Team" display name must not read as the bank ING (the extension's old false positive).
  assert.equal(assessRaw('Our spring sale starts today. https://shop.example.com/sale', 'Marketing Team <news@shop.example.com>').verdict, 'Safe');
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { checkUrl } from '../skills/syba-link-check/scripts/link-check.mjs';

test('link check: lookalikes and IDN homographs stop, genuine sites pass', () => {
  assert.equal(checkUrl('http://paypa1-secure-login.com/verify').verdict, 'Stop');
  const idn = checkUrl('https://аpple.com/account'); // Cyrillic "а"
  assert.equal(idn.verdict, 'Stop');
  assert.ok(idn.reasons.some((r) => r.id === 'idn_homograph'));
  assert.equal(checkUrl('https://www.paypal.com/signin').verdict, 'Safe');
  assert.equal(checkUrl('https://испытание.рф/').verdict, 'Safe'); // a genuine single-script IDN
  assert.equal(checkUrl('github.com/anthropics/skills').verdict, 'Safe');
});

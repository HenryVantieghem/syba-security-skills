import test from 'node:test';
import assert from 'node:assert/strict';
import { findSecrets, redact } from '../skills/syba-secret-hygiene/scripts/secret-scan.mjs';

// Fake values are assembled at run time so this file never holds a scannable secret.
const awsKey = 'AKIA' + 'Z7QXEXAMPLE2X4BQ';
const ghToken = 'ghp_' + 'aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5';
const card = '4111 1111' + ' 1111 1111';
const iban = 'BE71 0961' + ' 2345 6769';

test('secret scan: keys, cards and IBANs are found and redacted; ordinary numbers and env lookups are not', () => {
  const text = `aws=${awsKey}\ntoken: ${ghToken}\npay ${card} or ${iban}\n`;
  const kinds = findSecrets(text).map((f) => f.kind);
  assert.deepEqual(kinds, ['aws-access-key-id', 'github-token', 'card', 'iban']);
  const out = redact(text);
  for (const s of [awsKey, ghToken, card, iban]) assert.ok(!out.includes(s));

  const benign = 'const version = "1.2.3";\nconst id = 1234567890123456;\nconst api_key = process.env.API_KEY;\nconst total = 4111;';
  assert.deepEqual(findSecrets(benign), []);
});

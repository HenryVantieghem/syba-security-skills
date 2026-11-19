import test from 'node:test';
import assert from 'node:assert/strict';
import { scanLines } from '../skills/syba-security-review/scripts/review-scan.mjs';

const lines = (src) => src.split('\n').map((text, i) => ({ file: 'app.js', line: i + 1, text }));

test('security review: string-built SQL, raw HTML and open CORS are flagged; parameterised code is not', () => {
  const ids = scanLines(lines([
    'const rows = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);',
    'el.innerHTML = comment.body;',
    'app.use(cors({ origin: true, credentials: true }));',
  ].join('\n'))).map((h) => h.id);
  assert.deepEqual(ids, ['sql_concat', 'raw_html', 'cors_any_credentials']);
  assert.deepEqual(scanLines(lines("const rows = await db.query('SELECT * FROM users WHERE id = $1', [id]);\nel.textContent = comment.body;")), []);
});

import test from 'node:test';
import assert from 'node:assert/strict';
import { checkName, parseCommand } from '../skills/syba-dependency-trust/scripts/package-check.mjs';

test('dependency trust: known typosquats stop, real packages pass', () => {
  // crossenv was a real malicious npm typosquat of cross-env (2017).
  for (const n of ['lodahs', 'crossenv', 'l0dash', 'expresss']) assert.equal(checkName(n, 'npm').verdict, 'Stop', n);
  assert.equal(checkName('reqeusts', 'pypi').verdict, 'Stop');
  assert.equal(checkName('react-domjs', 'npm').verdict, 'Be careful');
  for (const n of ['lodash', 'cross-env', 'react-dom', '@types/node']) assert.equal(checkName(n, 'npm').verdict, 'Safe', n);
  assert.equal(checkName('Python_Dateutil', 'pypi').verdict, 'Safe');
  assert.deepEqual(parseCommand('pip install reqeusts numpy==2.1').map((p) => p.name), ['reqeusts', 'numpy']);
});

// The three answers every SYBA check gives, in plain words.
// Same ladder as the SYBA Shield extension's "Ask SYBA": Safe, Be careful, Stop.

export const LABEL = { safe: 'Safe', careful: 'Be careful', stop: 'Stop' };
const RANK = { safe: 0, careful: 1, stop: 2 };

/** Map the detectors' own verdict words onto the three-step ladder. */
export function levelOf(v) {
  if (v === 'phishing' || v === 'danger' || v === 'hostile' || v === 'stop' || v === 'high') return 'stop';
  if (v === 'suspicious' || v === 'caution' || v === 'careful' || v === 'medium') return 'careful';
  return 'safe';
}

export function worst(...levels) {
  return levels.reduce((a, b) => (RANK[b] > RANK[a] ? b : a), 'safe');
}

/** Exit code: 0 Safe, 10 Be careful, 20 Stop. Non-zero on purpose so scripts and hooks can gate on it. */
export function exitCodeFor(level) {
  return level === 'stop' ? 20 : level === 'careful' ? 10 : 0;
}

/** Read CLI input: file path, "-" for stdin, or the literal argument. */
export async function readInput(arg) {
  const fs = await import('node:fs');
  if (arg === '-' || arg === undefined) {
    if (process.stdin.isTTY) return '';
    const chunks = [];
    for await (const c of process.stdin) chunks.push(c);
    return Buffer.concat(chunks).toString('utf8');
  }
  try {
    if (fs.existsSync(arg) && fs.statSync(arg).isFile()) return fs.readFileSync(arg, 'utf8');
  } catch { /* not a path */ }
  return arg;
}

export function printReport({ title, level, reasons, next, json }, asJson) {
  if (asJson) {
    process.stdout.write(JSON.stringify({ verdict: LABEL[level], level, ...json }, null, 2) + '\n');
    return;
  }
  const lines = [`${LABEL[level]}: ${title}`];
  for (const r of reasons || []) lines.push(`  - ${r}`);
  if (next) lines.push(`Next step: ${next}`);
  process.stdout.write(lines.join('\n') + '\n');
}

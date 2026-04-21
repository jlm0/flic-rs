// Smoke test: load the .node from a plain Node context and exercise the
// `version()` export. Proves the binding builds + loads end-to-end before
// we add the real surface (FlicManager, event stream, commands).

import { version } from './index.js';

const reported = version();
console.log(`flic-napi loaded. version=${reported}`);

if (typeof reported !== 'string' || reported.length === 0) {
  console.error('FAIL: version() returned non-string or empty');
  process.exit(1);
}

console.log('OK');

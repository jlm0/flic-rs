// Smoke test for flic-napi. Runs under plain Node; exercises every
// no-hardware-required entry point. Hardware tests (pair/connect/press)
// live in hardware-smoke.mjs and need a button.

import { FlicManager, AdapterState, version } from './index.js';

function assert(cond, msg) {
  if (!cond) {
    console.error(`FAIL: ${msg}`);
    process.exit(1);
  }
}

console.log(`version=${version()}`);

const manager = await FlicManager.create();
console.log('FlicManager created');

const state = await manager.adapterState();
console.log(`adapterState=${state}`);
assert(
  state === AdapterState.PoweredOn ||
    state === AdapterState.PoweredOff ||
    state === AdapterState.Unknown,
  `adapterState returned unexpected value: ${state}`,
);

// Short scan — we don't expect any Public-Mode Flics, but the call should
// succeed and return an array without throwing.
const scanned = await manager.scan(2000);
console.log(`scan returned ${scanned.length} peripheral(s)`);
assert(Array.isArray(scanned), 'scan did not return an array');
for (const d of scanned) {
  assert(typeof d.id === 'string', 'Discovery.id is not a string');
  console.log(`  ${d.id} rssi=${d.rssi ?? 'none'} name=${d.localName ?? 'none'}`);
}

console.log('OK');

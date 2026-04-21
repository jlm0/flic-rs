// Hardware smoke test: connect to the paired button via the napi binding
// and log every event until Ctrl-C. Mirrors `flic-cli listen` but drives
// the JS API so we can prove the ThreadsafeFunction event path works.
//
// Expects a creds.json at ../../creds.json (flic-rs root) from the Phase 5
// pairing. Writes resume-state updates back every 10s.

import { readFileSync, writeFileSync, renameSync } from 'node:fs';
import { resolve } from 'node:path';
import { FlicManager } from './index.js';

const CREDS_PATH = resolve(process.cwd(), '../../creds.json');

const stored = JSON.parse(readFileSync(CREDS_PATH, 'utf8'));
const peripheralId = stored.peripheral_id;
const creds = {
  pairingId: stored.pairing_id,
  pairingKeyHex: stored.pairing_key_hex,
  serialNumber: stored.serial_number,
  buttonUuidHex: stored.button_uuid_hex,
  firmwareVersion: stored.firmware_version,
};
const resume = {
  eventCount: stored.resume_event_count ?? 0,
  bootId: stored.resume_boot_id ?? 0,
};

const manager = await FlicManager.create();
console.log(`adapter=${await manager.adapterState()}`);
console.log(`peripheral=${peripheralId} count=${resume.eventCount} boot=${resume.bootId}`);

manager.onEvent((ev) => {
  const short = ev.peripheralId.slice(0, 8);
  switch (ev.kind) {
    case 'connected':
      console.log(`[${short}] Connected battery=${ev.batteryMv}mV fw=${ev.firmware}`);
      break;
    case 'eventsResumed':
      console.log(
        `[${short}] EventsResumed count=${ev.eventCount} boot=${ev.bootId} queued=${ev.hasQueued}`,
      );
      break;
    case 'press':
      console.log(
        `[${short}] ${ev.pressKind} ts=${ev.timestamp32K}${ev.wasQueued ? ' (queued)' : ''}`,
      );
      break;
    case 'disconnected':
      console.log(`[${short}] Disconnected reason=${ev.reason?.kind}`);
      break;
    case 'reconnecting':
      console.log(
        `[${short}] Reconnecting in ${ev.afterMs}ms (attempt ${ev.attempt}) after ${ev.lastReason?.kind}`,
      );
      break;
    case 'adapterUnavailable':
      console.log(`[${short}] Adapter unavailable`);
      break;
    default:
      console.log('unknown event', ev);
  }
});

const handle = await manager.connect(peripheralId, creds, resume);
console.log('connected; click the button. Ctrl-C to stop.');

// Persist resume state every 10s — mirrors flic-cli's drainer.
const drainer = setInterval(() => {
  const current = handle.resumeState();
  if (!current) return;
  if (current.eventCount === resume.eventCount && current.bootId === resume.bootId) return;
  resume.eventCount = current.eventCount;
  resume.bootId = current.bootId;
  const updated = {
    ...stored,
    resume_event_count: current.eventCount,
    resume_boot_id: current.bootId,
    last_updated_utc: new Date().toISOString(),
  };
  const tmp = CREDS_PATH + '.tmp';
  writeFileSync(tmp, JSON.stringify(updated, null, 2));
  renameSync(tmp, CREDS_PATH);
  console.log(`creds updated count=${current.eventCount} boot=${current.bootId}`);
}, 10000);

const shutdown = async () => {
  console.log('disconnecting...');
  clearInterval(drainer);
  await handle.disconnect();
  process.exit(0);
};

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

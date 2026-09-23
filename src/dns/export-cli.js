#!/usr/bin/env node
import { exportBind, listZones } from './store.js';

const zone = process.argv[2];
if (!zone) {
  console.log('Usage: npm run export-zones -- <zone>');
  console.log('Zones:', listZones().join(', ') || '(none)');
  process.exit(zone === undefined ? 0 : 1);
}
const text = exportBind(zone);
if (!text) {
  console.error(`Zone not found: ${zone}`);
  process.exit(1);
}
process.stdout.write(text);

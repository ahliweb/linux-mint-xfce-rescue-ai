// Test-only stand-in for `osascript -l JavaScript -e SCRIPT` (JXA) on machines without macOS.
// It runs the SAME JavaScript source the launcher passes to osascript, behind a minimal ObjC
// facade (only the calls the launcher's planner uses), and prints the completion value like
// osascript does. Real JXA behavior on macOS is Hardware-required and is not covered here.
'use strict';
const fs = require('fs');
const vm = require('vm');

const args = process.argv.slice(2);
let script = null;
for (let i = 0; i < args.length; i++) {
  if (args[i] === '-e') { script = args[i + 1]; break; }
}
if (script === null) {
  process.stderr.write('osascript shim: only -e SCRIPT is supported\n');
  process.exit(64);
}

const box = (v) => ({ __v: v });
const ObjC = {
  import() {},
  unwrap(x) { return x !== null && typeof x === 'object' && '__v' in x ? x.__v : x; },
};
const dollar = function () { return null; };
dollar.NSUTF8StringEncoding = 4;
dollar.NSProcessInfo = {
  processInfo: {
    environment: { objectForKey: (name) => (process.env[name] === undefined ? null : box(process.env[name])) },
  },
};
dollar.NSString = {
  stringWithContentsOfFileEncodingError(path) {
    try { return box(fs.readFileSync(path, 'utf8')); } catch (e) { return null; }
  },
};

try {
  const result = vm.runInNewContext(script, { ObjC, $: dollar });
  if (result !== undefined && result !== null) process.stdout.write(String(result) + '\n');
} catch (e) {
  process.stderr.write('osascript shim: ' + (e && e.name ? e.name + ': ' + e.message : String(e)) + '\n');
  process.exit(1);
}

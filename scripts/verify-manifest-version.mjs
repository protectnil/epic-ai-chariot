#!/usr/bin/env node
// BUG-XXX: prepublish gate — fail if native/integrity.json version does not
// match package.json version. Prevents the BUG-XXX regression class where
// loadNativeBinding refuses to load the binary because the signed manifest
// is stale relative to the package version.

import { readFileSync } from 'node:fs';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
const manifest = JSON.parse(readFileSync(new URL('../native/integrity.json', import.meta.url), 'utf8'));

if (pkg.version !== manifest.version) {
  console.error('');
  console.error('  ERROR: native/integrity.json version does not match package.json');
  console.error('');
  console.error('    package.json:          ' + pkg.version);
  console.error('    native/integrity.json: ' + manifest.version);
  console.error('');
  console.error('  The signed integrity manifest was not regenerated for this');
  console.error('  release. Customers installing the package would have the');
  console.error('  native binary refuse to load (loadNativeBinding falls back');
  console.error('  to single-user mode), disabling the credential vault.');
  console.error('');
  console.error('  Regenerate via: npm run integrity:sign');
  console.error('  (or wait for release.yml sign-manifest job in CI)');
  console.error('');
  process.exit(1);
}

console.log('  ✓ native/integrity.json version (' + manifest.version + ') matches package.json');

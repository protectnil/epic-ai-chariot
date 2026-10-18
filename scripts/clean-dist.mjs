#!/usr/bin/env node
// Remove the compiled output tree before every build. `tsc` never deletes the
// outputs of a source file that was removed, and the npm tarball ships
// `dist/**/*`, so a stale compiled module would otherwise ship. Runs as the
// `prebuild` script; deleting only the build's own output directory.
import { rmSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

const dist = resolve(process.cwd(), 'dist');
if (existsSync(dist)) {
  rmSync(dist, { recursive: true, force: true });
  process.stdout.write('clean-dist: removed dist/\n');
} else {
  process.stdout.write('clean-dist: dist/ absent, nothing to remove\n');
}

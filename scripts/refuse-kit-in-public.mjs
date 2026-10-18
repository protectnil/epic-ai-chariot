#!/usr/bin/env node
// Public-package guard (dogfood-ready 4.0 offline-kit contract).
//
// package.json `files` includes `kit/**` so a recipient-specific tarball
// (`npm pack` with a kit/ directory staged at the repo root) carries that
// recipient's models, sealed shard, ONNX Runtime and licence. The PUBLIC
// npm package must never carry a kit: a licence envelope and a sealed shard
// are recipient secrets. This runs as the FIRST step of `prepublishOnly`
// and refuses `npm publish` while anything named `kit` exists at the repo
// root (directory, file or symbolic link).
//
// Built on the Epic AI® Intelligence Platform
// Copyright 2026 protectNIL Inc. Elastic-2.0

import { lstatSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const kitPath = join(repoRoot, 'kit');

let present = false;
try {
  lstatSync(kitPath);
  present = true;
} catch (err) {
  if (!err || err.code !== 'ENOENT') {
    console.error(`refusing to publish: cannot determine whether ${kitPath} exists (${err && err.message ? err.message : String(err)})`);
    process.exit(1);
  }
}

if (present) {
  console.error(
    `refusing to publish: ${kitPath} exists. An offline kit is recipient-specific ` +
    '(licence envelope, sealed catalog shard, models, ONNX Runtime) and must never ' +
    'ship in the public @epicai/chariot package. Move kit/ out of the working tree ' +
    'before `npm publish`; build recipient tarballs with `npm pack` only.',
  );
  process.exit(1);
}

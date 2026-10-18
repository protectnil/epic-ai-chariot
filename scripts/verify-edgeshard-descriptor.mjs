#!/usr/bin/env node
// Structural CI preflight; signature and license verification remain native
// startup responsibilities. This check must never claim cryptographic trust.
//
// CHARIOT §5.7 envelope fields (AMENDED 2026-10-14): `ciphertext` is either
// the file-reference form `{ "file": "<basename>", "sha256": "<hex>" }`
// (a bare basename resolved in the descriptor's own directory, naming a
// regular file, not a symbolic link) or the inline base64 form
// (`ciphertextB64`, with the legacy `ciphertext` alias equal to it). A
// descriptor carrying both forms is refused. The SHA-256 comparison below is
// a reference-integrity check of the staged file, not signature verification.
import { closeSync, constants as fsConstants, fstatSync, lstatSync, openSync, readFileSync, readSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { pathToFileURL } from 'node:url';

function sha256FileHex(path) {
  const fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
  try {
    if (!fstatSync(fd).isFile()) throw new Error('ciphertext file is not a regular file');
    const hash = createHash('sha256');
    const buf = Buffer.allocUnsafe(1 << 20);
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, null);
      if (n === 0) break;
      hash.update(buf.subarray(0, n));
    }
    return hash.digest('hex');
  } finally {
    closeSync(fd);
  }
}

function isBareBasename(file) {
  // Same rule as src/engine/retrieval/sealedShardConfig.ts isBareCiphertextBasename
  // (CHARIOT §5.7::61): only '.' and '..' themselves are refused, not a name
  // merely containing '..'.
  return typeof file === 'string' && file.length > 0 && file !== '.' && file !== '..' &&
    !file.includes('/') && !file.includes('\\') && !file.includes('\0');
}

function checkBase64(descriptor, name, length) {
  const value = descriptor[name];
  if (typeof value !== 'string' || !value || Buffer.from(value, 'base64').toString('base64') !== value) throw new Error(`invalid ${name}`);
  const bytes = Buffer.from(value, 'base64');
  if (length === null ? bytes.length < 16 : bytes.length !== length) throw new Error(`invalid ${name} length`);
}

export function verifyDescriptor(path, bundlePath = 'chariot-adapter-bundle.json') {
  const descriptor = JSON.parse(readFileSync(path, 'utf8'));
  const bundle = JSON.parse(readFileSync(bundlePath, 'utf8'));
  if (descriptor === null || typeof descriptor !== 'object' || Array.isArray(descriptor)) throw new Error('descriptor is not a JSON object');
  if (descriptor.iv !== descriptor.ivB64 || descriptor.signature !== descriptor.signatureB64) throw new Error('canonical envelope fields differ from consumer aliases');
  const ciphertext = descriptor.ciphertext;
  if (ciphertext !== null && typeof ciphertext === 'object' && !Array.isArray(ciphertext)) {
    if ('ciphertextB64' in descriptor) throw new Error('descriptor carries both the file-reference and the inline ciphertext forms');
    if (!isBareBasename(ciphertext.file)) throw new Error('ciphertext.file must be a bare basename');
    if (typeof ciphertext.sha256 !== 'string' || !/^[0-9a-f]{64}$/.test(ciphertext.sha256)) throw new Error('ciphertext.sha256 must be 64 lowercase hex characters');
    const ciphertextPath = join(dirname(path), ciphertext.file);
    const st = lstatSync(ciphertextPath);
    if (st.isSymbolicLink() || !st.isFile()) throw new Error('ciphertext file must be a regular file, not a symbolic link');
    if (st.size < 16) throw new Error('invalid ciphertext file length');
    if (sha256FileHex(ciphertextPath) !== ciphertext.sha256) throw new Error('ciphertext file SHA-256 differs from the descriptor');
  } else {
    if (ciphertext !== descriptor.ciphertextB64) throw new Error('canonical envelope fields differ from consumer aliases');
    checkBase64(descriptor, 'ciphertextB64', null);
  }
  checkBase64(descriptor, 'ivB64', 12);
  checkBase64(descriptor, 'signatureB64', 64);
  if (!Number.isSafeInteger(bundle.catalogVersion) || bundle.catalogVersion < 0 || descriptor.salt !== String(bundle.catalogVersion)) throw new Error('snapshot salt differs from signed catalog version');
  const match = /^([^|]+)\|epoch=(0|[1-9][0-9]*)$/.exec(descriptor.aad);
  if (!match || match[1] !== descriptor.salt || Number(match[2]) > 0xffffffff) throw new Error('invalid snapshot aad');
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  try {
    verifyDescriptor(process.argv[2] ?? 'artifacts/edgeshard/catalog.edgeshard.sealed', process.argv[3]);
    console.log('EdgeShard descriptor structure, ciphertext reference and catalog-version scope verified (not signature verification)');
  } catch {
    console.error('Invalid or absent EdgeShard descriptor (or its ciphertext file); produce and stage both before building the image.');
    process.exitCode = 1;
  }
}

#!/usr/bin/env node
/**
 * Epic AI® Chariot — §5.7 sealed EdgeShard snapshot producer (operator CLI)
 *
 * CHARIOT-SPEC §5.7 states: "The only encrypt-then-sign producer in this
 * repository is a `#[cfg(test)]` fixture." This script is the promotion of
 * that logic to real, reachable code: it drives the real native
 * `sealEdgeSnapshot` NAPI export (`native/src/edge_snapshot.rs`) to seal a
 * plaintext Edge snapshot archive into a `sealedShard` descriptor an operator
 * publishes alongside a catalog release, for `ChariotState.loadShard` (via
 * `sealedShardConfig.ts`) to later unseal and load.
 *
 * Usage:
 *   node dist/engine/bin/seal-edge-snapshot.js \
 *     --plaintext <path to plaintext snapshot archive> \
 *     --salt <catalog version identifier — see NOTE below> \
 *     --epoch <integer catalog epoch> \
 *     --out <path to write the sealedShard descriptor JSON>
 *
 * NOTE on --salt (CHARIOT::§5.7::16/37/38): `--salt` is the catalog version
 * identifier. The consumer derives its expected `<context>` from the TARGET
 * licence's signed `catalog_version` claim and rejects any mismatch
 * (salt == aad context == licence catalog_version), so `--salt` MUST equal
 * the `catalog_version` claim of the licence the shard is produced FOR.
 * Sealing for any other value produces a descriptor the intended consumer
 * rejects at unseal time (fail-closed, not silently accepted). The
 * catalog-bound producer `build-edgeshard-snapshot` enforces this itself.
 *
 * Reads secret material from the environment, NEVER from argv (argv is
 * visible in process listings):
 *   ENTERPRISE_MASTER_KEY        base64 32-byte secret root (CHARIOT::§5.7::10)
 *   CHARIOT_SEAL_SIGNING_SEED_B64  base64 32-byte raw Ed25519 signing-key seed
 *
 * `context` (the aad `<context>` segment) is always set equal to `--salt`
 * (CHARIOT::§5.7::16/17) — this CLI does not expose a separate `--context`
 * flag, so a caller cannot accidentally produce a self-inconsistent
 * descriptor.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { writeFileSync } from 'node:fs';
import { basename } from 'node:path';
import { loadNativeEdge } from '../retrieval/nativeEdge.js';

// master-key reference: VALIDATION ONLY (format/presence check, no derivation or encrypt/decrypt call)

interface Args {
  plaintext: string;
  salt: string;
  epoch: number;
  out: string;
}

function parseArgs(argv: string[]): Args {
  const get = (flag: string): string | undefined => {
    const i = argv.indexOf(flag);
    return i >= 0 ? argv[i + 1] : undefined;
  };
  const plaintext = get('--plaintext');
  const salt = get('--salt');
  const epochRaw = get('--epoch');
  const out = get('--out');
  if (!plaintext || !salt || !epochRaw || !out) {
    throw new Error(
      'usage: seal-edge-snapshot --plaintext <path> --salt <catalog version = target licence catalog_version> ' +
        '--epoch <int> --out <path>',
    );
  }
  const epoch = Number(epochRaw);
  if (!Number.isInteger(epoch) || epoch < 0) {
    throw new Error(`--epoch must be a non-negative integer, got ${epochRaw!}`);
  }
  return { plaintext, salt, epoch, out };
}

export function main(argv: string[] = process.argv.slice(2)): void {
  const args = parseArgs(argv);

  const secretRootB64 = process.env.ENTERPRISE_MASTER_KEY;
  if (!secretRootB64 || secretRootB64.trim() === '') {
    throw new Error(
      'ENTERPRISE_MASTER_KEY must be set (CHARIOT::§5.7::10 secret root — never pass it as an argv flag)',
    );
  }
  const signingKeySeedB64 = process.env.CHARIOT_SEAL_SIGNING_SEED_B64;
  if (!signingKeySeedB64 || signingKeySeedB64.trim() === '') {
    throw new Error(
      'CHARIOT_SEAL_SIGNING_SEED_B64 must be set to the base64 32-byte Ed25519 signing-key seed ' +
        '(never pass it as an argv flag). Its public key must be one of the compiled-in accepted ' +
        'keys (native/src/license.rs::ACCEPTED_PUBLIC_KEYS_PEM) for any consumer to unseal the result.',
    );
  }

  const native = loadNativeEdge();
  if (!native || typeof native.sealEdgeSnapshotFile !== 'function') {
    throw new Error(
      'native binary does not expose sealEdgeSnapshotFile; rebuild the native addon with the §5.7 producer',
    );
  }

  // File-reference form (CHARIOT §5.7): a catalog snapshot exceeds V8's
  // maximum string length, so the ciphertext is written beside the
  // descriptor as `<descriptor>.ciphertext` and referenced by basename.
  const ciphertextPath = `${args.out}.ciphertext`;
  const sealed = native.sealEdgeSnapshotFile(
    args.plaintext,
    ciphertextPath,
    secretRootB64,
    args.salt,
    args.salt, // context MUST equal salt (§5.7::16/17) — not independently exposed.
    args.epoch,
    signingKeySeedB64,
  );
  const descriptor = {
    ciphertext: { file: basename(ciphertextPath), sha256: sealed.ciphertextSha256Hex },
    iv: sealed.ivB64,
    signature: sealed.signatureB64,
    salt: sealed.salt,
    aad: sealed.aad,
    ivB64: sealed.ivB64,
    signatureB64: sealed.signatureB64,
  };
  writeFileSync(args.out, JSON.stringify(descriptor, null, 2), { flag: 'wx', mode: 0o600 });
  console.log(`sealed shard descriptor written to ${args.out} (ciphertext ${ciphertextPath})`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  try {
    main();
  } catch (err) {
    console.error(err instanceof Error ? err.message : String(err));
    process.exit(1);
  }
}

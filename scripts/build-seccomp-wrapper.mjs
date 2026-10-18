#!/usr/bin/env node
/**
 * @epicai/chariot — build the chariot-seccomp-wrapper binary (GAP #11).
 * Linux-only. On any other platform this is a deliberate, logged no-op:
 * ProcessSandbox.ts gates on `process.platform === 'linux'` before ever
 * looking for the compiled binary, so there is nothing for macOS/Windows
 * dev or CI to do here — and skipping the build there also avoids paying
 * the ~7 minute compile cost of this package's full dependency graph
 * (cargo resolves/builds the whole `chariot-native` package's deps even
 * for this single lightweight `libc`-only bin target) on platforms that
 * will never run it.
 *
 * Output is copied to the same flat, gitignored location the napi build
 * already uses for chariot-native.node: native/chariot-seccomp-wrapper.
 * Respects CARGO_TARGET_DIR if the caller has set it (defaults to cargo's
 * own default, native/target/).
 */
import { existsSync, copyFileSync, chmodSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { resolve as pathResolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = pathResolve(SCRIPT_DIR, '..');
const NATIVE_DIR = pathResolve(REPO_ROOT, 'native');
const BIN_NAME = 'chariot-seccomp-wrapper';
const DEST = pathResolve(NATIVE_DIR, BIN_NAME);

function main() {
  if (process.platform !== 'linux') {
    console.log(`[build-seccomp-wrapper] platform=${process.platform}: Linux-only artifact, skipping build (no-op).`);
    return;
  }

  const cargoTargetDir = process.env.CARGO_TARGET_DIR
    ? pathResolve(process.env.CARGO_TARGET_DIR)
    : pathResolve(NATIVE_DIR, 'target');
  const builtBinary = pathResolve(cargoTargetDir, 'release', BIN_NAME);

  console.log('[build-seccomp-wrapper] cargo build --release --bin chariot-seccomp-wrapper');
  execFileSync('cargo', ['build', '--release', '--bin', BIN_NAME, '--manifest-path', pathResolve(NATIVE_DIR, 'Cargo.toml')], {
    stdio: 'inherit',
    env: process.env,
  });

  if (!existsSync(builtBinary)) {
    console.error(`[build-seccomp-wrapper] expected built binary not found at ${builtBinary}`);
    process.exit(1);
  }

  copyFileSync(builtBinary, DEST);
  chmodSync(DEST, 0o755);
  console.log(`[build-seccomp-wrapper] installed ${DEST}`);
}

main();

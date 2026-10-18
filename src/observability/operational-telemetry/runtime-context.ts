/**
 * Operational-telemetry runtime context (C4AMD §8, closed nine-field set).
 *
 * Supplies the three build/runtime descriptors of the amended closed field
 * set — `productVersion`, `platform`, `catalogEpoch` — without any I/O
 * beyond a one-time read of this package's own package.json. Pure local
 * state: no network import (see `egress-guard.test.ts`).
 *
 * `catalogEpoch` is `null` until a signed catalog bundle has been admitted
 * in this process. ABSENT is not zero: an unloaded catalog must never be
 * reported as epoch 0.
 */

import { createRequire } from 'node:module';
import { arch, platform } from 'node:os';

let _catalogEpoch: number | null = null;
let _productVersion: string | null = null;

/** Called by the catalog admission path once a signed bundle's epoch has been accepted. */
export function recordLoadedCatalogEpoch(epoch: number): void {
  if (Number.isInteger(epoch) && epoch >= 0) _catalogEpoch = epoch;
}

export function getLoadedCatalogEpoch(): number | null {
  return _catalogEpoch;
}

/**
 * Installed `@epicai/chariot` version from this package's package.json, or
 * `null` when it cannot be read (C4AMD §8: `productVersion` IS the installed
 * package version — there is no "unknown" value, so capture skips the event
 * rather than emit something that is not the installed version).
 */
export function getProductVersion(): string | null {
  if (_productVersion !== null) return _productVersion;
  try {
    const req = createRequire(import.meta.url);
    const v = (req('../../../package.json') as { version?: unknown }).version;
    if (typeof v === 'string' && /^[0-9A-Za-z.+_-]{1,64}$/.test(v)) _productVersion = v;
  } catch {
    // unreadable: stays null
  }
  return _productVersion;
}

/** Host `<os>-<arch>` key, e.g. `linux-arm64`, `darwin-arm64`, `win32-x64`. */
export function getPlatformKey(): string {
  return `${platform()}-${arch()}`.toLowerCase();
}

/** Test-only reset. */
export function __resetRuntimeContextForTests(): void {
  _catalogEpoch = null;
  _productVersion = null;
}

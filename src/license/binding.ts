/**
 * Native binding loader for the Chariot Rust binary.
 * Attempts to load the platform-specific napi-rs addon.
 * Falls back gracefully to null if the binary is not available
 * (e.g., on an unsupported platform — single-user mode).
 */

import { createRequire } from 'node:module';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync, existsSync } from 'node:fs';
import { arch, platform } from 'node:os';
import { dirname, join } from 'node:path';

interface NativeBinding {
  validateLicense(licenseJson: string, signatureB64: string): {
    valid: boolean;
    companyId?: string;
    companyName?: string;
    totalSeats?: number;
    issuedAt?: string;
    expiresAt?: string;
    reason?: string;
  };
  /**
   * Native RBAC check, tenant-scoped. The caller's `tenantId` is the
   * authoritative tenant context; any entry in `mappingsJson` whose
   * `tenantId` differs causes `allowed: false` with a non-empty `reason`.
   * Defense against a TS caller that accidentally constructs a
   * cross-tenant mappings array.
   *
   * `mappingsJson` shape: `[{ tenantId, groupId, adapterIds }, ...]`
   */
  checkAccess(
    tenantId: string,
    userGroups: string[],
    requestedAdapterIds: string[],
    mappingsJson: string
  ): {
    allowed: boolean;
    grantedAdapterIds: string[];
    deniedAdapterIds: string[];
    reason?: string;
  };
  /**
   * Resolve a user's accessible adapter IDs within the caller's tenant.
   * Mappings whose `tenantId` does not match are silently filtered out;
   * see `checkAccess` for the hard-error variant.
   */
  resolveUserAdapters(tenantId: string, userGroups: string[], mappingsJson: string): string[];
  encryptCredential(
    plaintext: string,
    tenantId: string,
    masterKeyB64: string
  ): { encrypted: string; iv: string };
  decryptCredential(
    encryptedB64: string,
    ivB64: string,
    tenantId: string,
    masterKeyB64: string
  ): string;
  discoverInternalApis(codebasePath: string): {
    services: Array<{
      name: string;
      framework: string;
      basePath: string;
      endpoints: Array<{
        method: string;
        path: string;
        handlerName?: string;
        filePath: string;
        lineNumber: number;
      }>;
      specFile?: string;
    }>;
    totalEndpoints: number;
    scanDurationMs: number;
  };
}

function getPlatformPackage(): string {
  const p = platform();
  const a = arch();

  const platformMap: Record<string, string> = {
    'linux-x64': '@epicai/chariot-bin-linux-x64-gnu',
    'darwin-arm64': '@epicai/chariot-bin-darwin-arm64',
    'darwin-x64': '@epicai/chariot-bin-darwin-x64',
    'win32-x64': '@epicai/chariot-bin-win32-x64-msvc',
  };

  const key = `${p}-${a}`;
  const pkg = platformMap[key];

  if (!pkg) {
    throw new Error(
      `Unsupported platform: ${p}-${a}. ` +
      `Chariot enterprise features require one of: linux-x64, darwin-arm64, darwin-x64, win32-x64`
    );
  }

  return pkg;
}

let _binding: NativeBinding | null = null;
let _loadAttempted = false;
let _loadError: string | null = null;
let _binaryHash: string | null = null;

/**
 * Verify the loaded binding has the expected interface.
 * This is a structural integrity check — not cryptographic, but catches
 * corrupted or replaced binaries that don't implement the full API.
 */
function verifyBindingInterface(binding: unknown): binding is NativeBinding {
  if (!binding || typeof binding !== 'object') return false;
  const b = binding as Record<string, unknown>;
  const requiredFunctions = [
    'validateLicense', 'checkAccess', 'resolveUserAdapters',
    'encryptCredential', 'decryptCredential', 'discoverInternalApis',
  ];
  for (const fn of requiredFunctions) {
    if (typeof b[fn] !== 'function') return false;
  }
  return true;
}

/**
 * Perform a functional smoke test on the loaded binding.
 * Calls validateLicense with known-bad input to verify the binary
 * actually executes and returns the expected structure.
 * This catches corrupted binaries that pass interface checks but crash at runtime.
 */
function functionalSmokeTest(binding: NativeBinding): boolean {
  try {
    const result = binding.validateLicense('{}', '');
    // Empty payload + empty signature must return valid: false
    return result !== null && typeof result === 'object' && result.valid === false;
  } catch {
    return false;
  }
}

/**
 * Resolve the filesystem path of the native binary.
 * Returns the resolved path or null if not resolvable.
 */
function resolveBinaryPath(requireFn: NodeRequire): string | null {
  try {
    return requireFn.resolve('../../native/chariot-native.node');
  } catch {
    try {
      const pkg = getPlatformPackage();
      return requireFn.resolve(pkg);
    } catch {
      return null;
    }
  }
}

/**
 * Compute SHA-256 hash of the native binary file.
 * Returns null if the file cannot be read.
 */
function computeBinaryHash(binaryPath: string): string | null {
  try {
    const content = readFileSync(binaryPath);
    return createHash('sha256').update(content).digest('hex');
  } catch {
    return null;
  }
}

// ── Signed integrity manifest ─────────────────────────────────────────────
//
// The integrity manifest (native/integrity.json) contains SHA-256 hashes of
// each platform binary, signed with the same Ed25519 key used for license
// signing. At load time we:
//   1. Resolve the binary file path
//   2. Compute its SHA-256 hash
//   3. Read the integrity manifest from the same directory
//   4. Verify the manifest signature using the embedded public key
//   5. Compare the computed hash against the manifest entry for this platform
//   6. FAIL CLOSED on missing manifest, bad signature, or hash mismatch
//
// This prevents a replaced binary from being accepted even if it passes
// the interface check and functional smoke test.

/** Ed25519 public key for integrity manifest verification (same key as license signing). */
const INTEGRITY_PUBLIC_KEY_PEM =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MCowBQYDK2VwAyEAaAjNCRAxZlceSqsD3HXRK5HaxYlAtDEIyhebMycQUa8=\n' +
  '-----END PUBLIC KEY-----';

/**
 * Module-level cached KeyObject for integrity manifest verification (REUSE #7).
 *
 * `createPublicKey` is called exactly once per process lifetime. Both the v1
 * and v2 payload paths inside `verifyManifestSignature` use this cached object.
 *
 * Note: `INTEGRITY_PUBLIC_KEY_PEM` uses a different Ed25519 key than the
 * license-signing keys in `loader.ts` (those are keyed by `kid` and live in
 * `ACCEPTED_KEYS_PEM`). The two key spaces are intentionally separate — the
 * manifest key signs binary integrity data; the license keys sign JWT claims.
 * We do not share the `getCachedPublicKeys()` helper from loader.ts here because
 * the keys are different and mixing the namespaces would weaken the integrity
 * boundary.
 */
const _integrityPublicKey = createPublicKey(INTEGRITY_PUBLIC_KEY_PEM);

interface IntegrityManifest {
  version?: string;
  commit?: string;
  timestamp?: string;
  hashes: Record<string, string>;
  signature: string;
}

/**
 * Read the package version from the nearest package.json.
 * Used to verify the manifest is bound to the current release.
 */
function getPackageVersion(requireFn: NodeRequire): string | null {
  try {
    const pkgPath = requireFn.resolve('../../package.json');
    const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8')) as { version?: string };
    return pkg.version ?? null;
  } catch {
    return null;
  }
}

/**
 * Verify the Ed25519 signature on a manifest.
 * Supports v2 (signature over { version, commit, timestamp, hashes })
 * and v1 (signature over hashes only) for backward compatibility.
 * Returns true if the signature is valid under either format.
 *
 * Key reuse (REUSE #7): uses the module-level `_integrityPublicKey` cached
 * at import time — `createPublicKey` is never called inside this function.
 *
 * Serialization note (REUSE #12): payloads are serialized with `JSON.stringify`
 * rather than `canonicalStringify` from src/util/canonical-json.ts.
 * This is intentional: existing manifests in the field were signed during
 * build with `JSON.stringify`. Switching to `canonicalStringify` would change
 * the byte sequence for any object whose keys are not already in ASCII sort
 * order (e.g., `{ version, commit, timestamp, hashes }` — "commit" < "hashes"
 * < "timestamp" < "version" in ASCII, so the canonical form differs from the
 * insertion order used during signing). Re-signing all manifests in deployed
 * packages is not viable without a coordinated release, so we keep
 * `JSON.stringify` on the verify path to preserve compatibility with all
 * existing signed artifacts. If a future major release re-signs manifests
 * with `canonicalStringify`, add a v3 payload branch here.
 */
function verifyManifestSignature(manifest: IntegrityManifest): boolean {
  try {
    const sig = Buffer.from(manifest.signature, 'base64');

    // v2: signature over full release record
    if (manifest.version && manifest.commit && manifest.timestamp) {
      const v2Payload = JSON.stringify({
        version: manifest.version,
        commit: manifest.commit,
        timestamp: manifest.timestamp,
        hashes: manifest.hashes,
      });
      if (verify(null, Buffer.from(v2Payload), _integrityPublicKey, sig)) return true;
    }

    // v1 fallback: signature over hashes only
    const v1Payload = JSON.stringify(manifest.hashes);
    return verify(null, Buffer.from(v1Payload), _integrityPublicKey, sig);
  } catch {
    return false;
  }
}

/**
 * Verify the native binary against the signed integrity manifest.
 * Returns null on success, or an error message describing the failure.
 *
 * Checks (all must pass):
 *   1. Manifest exists alongside the binary
 *   2. Manifest parses as valid JSON with required fields
 *   3. Ed25519 signature is valid
 *   4. Manifest version matches the package version (v2 only)
 *   5. Platform hash entry exists
 *   6. Computed binary hash matches the manifest entry
 */
function verifyIntegrityManifest(
  binaryPath: string,
  computedHash: string,
  requireFn: NodeRequire,
): string | null {
  const platformKey = `${platform()}-${arch()}`;
  const binaryDir = dirname(binaryPath);

  // 1. Locate the manifest
  let manifestPath: string | null = null;
  for (const candidate of [
    join(binaryDir, 'integrity.json'),
    join(binaryDir, '..', 'native', 'integrity.json'),
  ]) {
    if (existsSync(candidate)) {
      manifestPath = candidate;
      break;
    }
  }

  if (!manifestPath) {
    return 'Integrity manifest (integrity.json) not found alongside native binary. ' +
      'The binary cannot be verified. Reinstall @epicai/chariot.';
  }

  // 2. Parse the manifest
  let manifest: IntegrityManifest;
  try {
    const raw = readFileSync(manifestPath, 'utf-8');
    manifest = JSON.parse(raw) as IntegrityManifest;
  } catch {
    return 'Integrity manifest is corrupted or unreadable.';
  }

  if (!manifest.hashes || typeof manifest.hashes !== 'object' || !manifest.signature) {
    return 'Integrity manifest has invalid structure (missing hashes or signature).';
  }

  // 3. Verify the Ed25519 signature
  if (!verifyManifestSignature(manifest)) {
    return 'Integrity manifest signature verification failed. ' +
      'The manifest may have been tampered with.';
  }

  // 4. Version binding check (v2 manifests only)
  if (manifest.version) {
    const pkgVersion = getPackageVersion(requireFn);
    if (pkgVersion && manifest.version !== pkgVersion) {
      return `Integrity manifest version "${manifest.version}" does not match ` +
        `package version "${pkgVersion}". The manifest is stale. ` +
        'Reinstall @epicai/chariot or regenerate the manifest.';
    }
  }

  // 5. Platform hash entry
  const expectedHash = manifest.hashes[platformKey];
  if (!expectedHash) {
    return `Integrity manifest has no entry for platform "${platformKey}". ` +
      'Reinstall @epicai/chariot for this platform.';
  }

  // 6. Hash comparison
  if (computedHash !== expectedHash) {
    return `Native binary hash mismatch for ${platformKey}. ` +
      `Expected: ${expectedHash.slice(0, 16)}... ` +
      `Got: ${computedHash.slice(0, 16)}... ` +
      'The binary may have been replaced or corrupted.';
  }

  return null; // All checks passed
}

/**
 * Load the native Chariot binary.
 * Returns null if the binary is not installed (single-user mode).
 *
 * Verification pipeline (all must pass, fail closed):
 *   1. Interface check — all required functions exist
 *   2. Functional smoke test — binary executes and returns expected structure
 *   3. Signed integrity manifest — SHA-256 hash matches Ed25519-signed manifest
 */
export function loadNativeBinding(): NativeBinding | null {
  if (_loadAttempted) return _binding;
  _loadAttempted = true;

  try {
    const require = createRequire(import.meta.url);
    let candidate: unknown;

    // First try loading from the local native/ directory (development)
    try {
      candidate = require('../../native/chariot-native.node');
    } catch {
      // Not in development, try platform package
      const pkg = getPlatformPackage();
      candidate = require(pkg);
    }

    // Step 1: Verify the loaded artifact has the expected interface
    if (!verifyBindingInterface(candidate)) {
      _loadError = 'Native binary loaded but failed interface verification. ' +
        'The binary may be corrupted, incompatible, or replaced. ' +
        'Enterprise mode is disabled.';
      _binding = null;
      return null;
    }

    // Step 2: Functional smoke test — verify the binary executes correctly
    if (!functionalSmokeTest(candidate)) {
      _loadError = 'Native binary loaded but failed functional smoke test. ' +
        'The binary may be corrupted or incompatible with this version. ' +
        'Enterprise mode is disabled.';
      _binding = null;
      return null;
    }

    // Step 3: Signed integrity manifest — verify hash against trusted manifest
    const binaryPath = resolveBinaryPath(require);
    if (binaryPath) {
      const computedHash = computeBinaryHash(binaryPath);
      if (computedHash) {
        _binaryHash = computedHash;
        const integrityError = verifyIntegrityManifest(binaryPath, computedHash, require);
        if (integrityError) {
          _loadError = `Native binary integrity check failed: ${integrityError} ` +
            'Enterprise mode is disabled.';
          _binding = null;
          return null;
        }
      } else {
        // Cannot compute hash — cannot verify. Fail closed.
        _loadError = 'Cannot read native binary file to compute integrity hash. ' +
          'Enterprise mode is disabled.';
        _binding = null;
        return null;
      }
    } else {
      // Cannot resolve path — cannot verify. Fail closed.
      _loadError = 'Cannot resolve native binary file path for integrity verification. ' +
        'Enterprise mode is disabled.';
      _binding = null;
      return null;
    }

    _binding = candidate;
    return _binding;
  } catch (loadErr) {
    // Reached only when `require()` throws — typically because the binary
    // is not installed (single-user mode) or because the platform package
    // cannot be loaded (wrong ABI, missing glibc version, unresolvable
    // transitive dep). Capture the actual error message so operators can
    // tell the difference between "not installed" (expected) and "installed
    // but unloadable" (bug).
    const msg = loadErr instanceof Error ? loadErr.message : String(loadErr);
    _loadError =
      `Native binary not loaded (${msg}). ` +
      'If you installed @epicai/chariot and expected the native binary to be present, ' +
      'check that a matching platform package is installed: ' +
      '@epicai/chariot-bin-linux-x64-gnu, @epicai/chariot-bin-darwin-arm64, ' +
      '@epicai/chariot-bin-darwin-x64, or @epicai/chariot-bin-win32-x64-msvc. ' +
      'Running in single-user mode.';
    _binding = null;
    return null;
  }
}

/**
 * Get the last load error, if any.
 * Used by CLI and startup to report why the binary is unavailable.
 */
export function getBindingLoadError(): string | null {
  return _loadError;
}

/**
 * Get the SHA-256 hash of the loaded native binary, or null if not available.
 * Used for audit logging and integrity tracking.
 */
export function getBindingHash(): string | null {
  return _binaryHash;
}

/**
 * Get the native binding, throwing if not available.
 * Use this in code paths that require the enterprise binary.
 *
 * Item 11: If verification failed, this throws with the specific reason
 * rather than a generic "not available" message.
 */
export function requireNativeBinding(): NativeBinding {
  const binding = loadNativeBinding();
  if (!binding) {
    const reason = _loadError || 'Native binary not available.';
    throw new Error(
      `Chariot enterprise features require the native binary. ${reason} ` +
      'Install the matching platform package for @epicai/chariot to enable IAM, ' +
      'RBAC, credential vault, and internal API discovery.'
    );
  }
  return binding;
}

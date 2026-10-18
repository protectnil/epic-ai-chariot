/**
 * Native binding loader for the Chariot Rust binary.
 * Attempts to load the platform-specific napi-rs addon.
 * Falls back gracefully to null if the binary is not available
 * (e.g., on an unsupported platform — single-user mode).
 */

import { createRequire } from 'node:module';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFileSync, existsSync, openSync, readSync, closeSync } from 'node:fs';
import { arch, platform } from 'node:os';
import { dirname, join } from 'node:path';

export interface NativeBinding {
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
   * Deny-by-default: an EMPTY `requestedAdapterIds` list returns
   * `allowed: false` (nothing to authorize — a vacuous request is never
   * success). Deny-precedence: any user-held group mapping with an empty
   * `adapterIds` list is an explicit deny overriding all grants. Group ids
   * are matched case-insensitively.
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
   *
   * Semantics are identical to `checkAccess` (shared native helper):
   * group ids match case-insensitively, and an empty result may mean
   * EXPLICIT DENY (a user-held group mapping with empty `adapterIds`),
   * not just "no grants" — never treat this output as display-only truth
   * while enforcing with different logic.
   */
  resolveUserAdapters(tenantId: string, userGroups: string[], mappingsJson: string): string[];
  /**
   * Principal-aware variant of `checkAccess` (gap #3 — Wiz 2 human/agent
   * partition). Identical contract to `checkAccess` PLUS a mandatory
   * `principalType` argument identifying the CALLER: "human" | "agent" |
   * "service" (case-insensitive; native fails closed — denies with a
   * structured reason — on anything else). Any mapping whose
   * `principalScope` is a non-empty list that does not include the
   * caller's kind is not honored for this call, so an agent/service
   * caller cannot inherit a mapping an operator scoped to humans only.
   *
   * Optional on this interface (unlike `checkAccess`/`resolveUserAdapters`
   * in `verifyBindingInterface`'s required-functions list) so a binary
   * built before this native export existed still loads — callers that
   * need the principal-kind partition MUST feature-detect
   * (`typeof binding.checkAccessForPrincipal === 'function'`) before use.
   */
  checkAccessForPrincipal?(
    tenantId: string,
    principalType: 'human' | 'agent' | 'service',
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
   * Principal-aware variant of `resolveUserAdapters` (gap #3). See
   * `checkAccessForPrincipal` for the principal-scope semantics. Returns
   * an empty list on JSON parse error, invalid `principalType`, when no
   * in-tenant mappings match, OR on explicit deny.
   */
  resolveUserAdaptersForPrincipal?(
    tenantId: string,
    principalType: 'human' | 'agent' | 'service',
    userGroups: string[],
    mappingsJson: string
  ): string[];
  /**
   * CH-10 (§12.2): `adapterId` is bound into the AES-GCM AAD alongside
   * `tenantId` so a ciphertext cannot be relocated from one adapter's row
   * to another within the same tenant and still decrypt. Callers that do
   * not have a literal catalog adapter (e.g. an OIDC client-secret row, an
   * ID-JAG subject-token row) MUST still pass a stable, unique-within-tenant
   * identifier for that record so the same anti-relocation binding applies.
   */
  encryptCredential(
    plaintext: string,
    tenantId: string,
    adapterId: string,
    masterKeyB64: string
  ): { encrypted: string; iv: string };
  /**
   * `legacyAllowed` (CHARIOT §12.2, CH-10, rulings item 59): whether an
   * UNPREFIXED (legacy, empty-AAD) ciphertext may be decrypted in the
   * current context. Ignored for `v2:`-prefixed (AAD-bound) records.
   * Native-layer enforcement — see `native/src/vault.rs::decrypt_credential`
   * and `src/iam/crypto.ts::resolveLegacyDecryptPolicy`.
   */
  decryptCredential(
    encryptedB64: string,
    ivB64: string,
    tenantId: string,
    adapterId: string,
    masterKeyB64: string,
    legacyAllowed: boolean
  ): string;
  /**
   * CH-10 (rulings item 59) capability probe. OPTIONAL: absent on any
   * binary compiled before this change (e.g. the currently signed Sep-1
   * build) — its absence MUST be treated as "the legacy-ciphertext gate is
   * unsupported", never as "legacy decryption is allowed". See
   * `src/iam/crypto.ts::hasVaultLegacyGate()`.
   */
  vaultProtocolVersion?(): number;
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
    'linux-arm64': '@epicai/chariot-bin-linux-arm64-gnu',
    'darwin-arm64': '@epicai/chariot-bin-darwin-arm64',
    'darwin-x64': '@epicai/chariot-bin-darwin-x64',
    'win32-x64': '@epicai/chariot-bin-win32-x64-msvc',
  };

  const key = `${p}-${a}`;
  const pkg = platformMap[key];

  if (!pkg) {
    throw new Error(
      `Unsupported platform: ${p}-${a}. ` +
      `Chariot enterprise features require one of: linux-x64, linux-arm64, darwin-arm64, darwin-x64, win32-x64`
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
 * The native addon, loaded only after its SHA-256 matched the Ed25519-signed
 * integrity manifest. Shared by every loader of `chariot-native.node`
 * (`loadNativeBinding` here, and `loadNativeEdge` in
 * src/engine/retrieval/nativeEdge.ts) so no code path requires the addon
 * without the manifest check (CHARIOT §3.5::10, §12.6::2, §12.6::3).
 *
 *   integrity  — a candidate exists but none matched the signed manifest, the
 *                file could not be read for hashing, or it changed on disk
 *                between verification and load. Fail closed.
 *   unloadable — nothing is installed, or the verified file could not be
 *                required (wrong ABI, missing glibc, unresolvable dep).
 */
export type VerifiedNativeModule =
  | { ok: true; module: unknown; path: string; hash: string }
  | { ok: false; kind: 'integrity' | 'unloadable'; message: string };

let _verifiedNative: VerifiedNativeModule | null = null;

/**
 * Resolve, verify and load the native addon. Idempotent (cached after the
 * first call).
 *
 * Order (all must pass, fail closed):
 *   0. Signed integrity manifest — SHA-256 of THE selected file matches the
 *      Ed25519-signed manifest entry for this platform, checked BEFORE the
 *      file is required. Exactly one file is selected, by what it is built
 *      for (see nativeBinaryIsBuiltForHost), not by whether it verifies: the
 *      bundled native/ file when its header says it is built for this host,
 *      else the platform sibling package (the bundled file is the linux-x64
 *      build, so on linux-arm64/darwin/win32 installs it is not the host's
 *      binary). A hash mismatch on the selected file never falls through to
 *      another file.
 *   1. require() only the verified file.
 *   2. Re-hash that path after load. Path-based dlopen cannot pin the bytes
 *      it maps, so this narrows (it does not remove) the window in which the
 *      file could be replaced between hash and load; a replaced file is
 *      detected and the binding is never returned.
 */
export function loadVerifiedNativeModule(): VerifiedNativeModule {
  if (_verifiedNative) return _verifiedNative;
  _verifiedNative = resolveVerifiedNativeModule();
  return _verifiedNative;
}

/**
 * True when the file's executable header says it was built for this process's
 * platform and CPU. A compatibility test (ELF e_machine, Mach-O cputype, PE
 * Machine), not an integrity test: it only decides WHICH single file is
 * verified. Unknown or unreadable headers return false.
 */
function nativeBinaryIsBuiltForHost(filePath: string): boolean {
  let header: Buffer;
  let fd: number | null = null;
  try {
    fd = openSync(filePath, 'r');
    header = Buffer.alloc(4096);
    const n = readSync(fd, header, 0, header.length, 0);
    header = header.subarray(0, n);
  } catch {
    return false;
  } finally {
    if (fd !== null) {
      try { closeSync(fd); } catch { /* ignore */ }
    }
  }
  const cpu = arch();
  const os = platform();
  if (header.length < 64) return false;

  // ELF: 7f 'E' 'L' 'F', EI_CLASS 2 (64-bit), EI_DATA 1 (little endian)
  if (header[0] === 0x7f && header[1] === 0x45 && header[2] === 0x4c && header[3] === 0x46) {
    if (os !== 'linux' || header[4] !== 2 || header[5] !== 1) return false;
    const machine = header.readUInt16LE(18);
    return (cpu === 'x64' && machine === 0x3e) || (cpu === 'arm64' && machine === 0xb7);
  }
  // Mach-O 64-bit little endian: CF FA ED FE, cputype u32 LE at offset 4
  if (header.readUInt32LE(0) === 0xfeedfacf) {
    if (os !== 'darwin') return false;
    const cputype = header.readUInt32LE(4);
    return (cpu === 'x64' && cputype === 0x01000007) || (cpu === 'arm64' && cputype === 0x0100000c);
  }
  // PE: 'MZ', e_lfanew u32 LE at 0x3C -> 'PE\0\0', Machine u16 LE after it
  if (header[0] === 0x4d && header[1] === 0x5a) {
    if (os !== 'win32') return false;
    const peOffset = header.readUInt32LE(0x3c);
    if (peOffset + 6 > header.length || header.readUInt32LE(peOffset) !== 0x00004550) return false;
    const machine = header.readUInt16LE(peOffset + 4);
    return (cpu === 'x64' && machine === 0x8664) || (cpu === 'arm64' && machine === 0xaa64);
  }
  return false;
}

function resolveVerifiedNativeModule(): VerifiedNativeModule {
  const require = createRequire(import.meta.url);

  // Exactly ONE candidate is selected, by what the file is built for, never by
  // whether its hash happens to verify — so a hash mismatch is always a hard
  // fail-closed and never falls through to another file (CHARIOT §12.6::3):
  //   1. the bundled native/ file, when its binary header says it is built for
  //      this host (development builds; linux-x64 installs; container images);
  //   2. else the platform sibling package (linux-arm64/darwin/win32 installs,
  //      where the bundled file is the linux-x64 build);
  //   3. else the bundled file, and let verification decide.
  let bundledPath: string | null = null;
  let siblingPath: string | null = null;
  let resolveError: unknown;
  try {
    bundledPath = require.resolve('../../native/chariot-native.node');
  } catch (err) {
    resolveError = err;
  }
  try {
    siblingPath = require.resolve(getPlatformPackage());
  } catch (err) {
    resolveError = resolveError ?? err;
  }
  const binaryPath =
    bundledPath && nativeBinaryIsBuiltForHost(bundledPath) ? bundledPath : (siblingPath ?? bundledPath);
  if (!binaryPath) {
    const message = resolveError instanceof Error ? resolveError.message : 'native binary not found';
    return { ok: false, kind: 'unloadable', message };
  }

  const verifiedHash = computeBinaryHash(binaryPath);
  if (!verifiedHash) {
    // Cannot compute hash — cannot verify. Fail closed.
    return {
      ok: false,
      kind: 'integrity',
      message: 'Cannot read native binary file to compute integrity hash.',
    };
  }
  const integrityError = verifyIntegrityManifest(binaryPath, verifiedHash, require);
  if (integrityError) {
    return {
      ok: false,
      kind: 'integrity',
      message: `Native binary integrity check failed: ${integrityError}`,
    };
  }
  const verifiedPath = binaryPath;

  let loaded: unknown;
  try {
    // Load only the verified file.
    // eslint-disable-next-line local/no-dynamic-module-specifier -- DYNAMIC_LOADER_SITES: native addon path resolved from the fixed bundled location or getPlatformPackage() and integrity-verified above
    loaded = require(verifiedPath);
  } catch (err) {
    return {
      ok: false,
      kind: 'unloadable',
      message: err instanceof Error ? err.message : String(err),
    };
  }

  if (computeBinaryHash(verifiedPath) !== verifiedHash) {
    return {
      ok: false,
      kind: 'integrity',
      message: 'Native binary integrity check failed: the binary changed on disk between verification and load.',
    };
  }

  return { ok: true, module: loaded, path: verifiedPath, hash: verifiedHash };
}

/**
 * Load the native Chariot binary.
 * Returns null if the binary is not installed (single-user mode).
 *
 * Verification pipeline (all must pass, fail closed):
 *   0. Signed integrity manifest, checked before the addon is loaded
 *      (loadVerifiedNativeModule)
 *   1. Interface check — all required functions exist
 *   2. Functional smoke test — binary executes and returns expected structure
 */
export function loadNativeBinding(): NativeBinding | null {
  if (_loadAttempted) return _binding;
  _loadAttempted = true;

  const notLoaded = (msg: string): null => {
    // "not installed" (expected) is distinguished from "installed but
    // unloadable" (bug) by the captured message.
    _loadError =
      `Native binary not loaded (${msg}). ` +
      'If you installed @epicai/chariot and expected the native binary to be present, ' +
      'check that a matching platform package is installed: ' +
      '@epicai/chariot-bin-linux-x64-gnu, @epicai/chariot-bin-linux-arm64-gnu, ' +
      '@epicai/chariot-bin-darwin-arm64, ' +
      '@epicai/chariot-bin-darwin-x64, or @epicai/chariot-bin-win32-x64-msvc. ' +
      'Running in single-user mode.';
    _binding = null;
    return null;
  };

  try {
    const verified = loadVerifiedNativeModule();
    if (!verified.ok) {
      if (verified.kind === 'integrity') {
        _loadError = `${verified.message} Enterprise mode is disabled.`;
        _binding = null;
        return null;
      }
      return notLoaded(verified.message);
    }
    const candidate = verified.module;

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

    _binaryHash = verified.hash;
    _binding = candidate;
    return _binding;
  } catch (loadErr) {
    return notLoaded(loadErr instanceof Error ? loadErr.message : String(loadErr));
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

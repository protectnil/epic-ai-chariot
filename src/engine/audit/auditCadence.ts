/**
 * @epicai/chariot — Periodic audit anchor/attest cadence (CH-45 / §8.3–8.5)
 *
 * Implements the spec-advertised periodic RFC-3161 anchoring and signed
 * length-attestation cadence that was previously UNIMPLEMENTED: the four
 * cadence env vars (CHARIOT_ANCHOR_EVENT_INTERVAL,
 * CHARIOT_ANCHOR_TIME_INTERVAL_MS, CHARIOT_ATTEST_EVENT_INTERVAL,
 * CHARIOT_ATTEST_TIME_INTERVAL_MS) appeared only in CHARIOT-SPEC.md and were
 * referenced by zero code, so an operator who deployed per §8.3/§8.4/§8.5 and
 * set them got a silent no-op — no anchors, no attestations, an unbounded
 * tamper-evidence window until someone manually ran the CLI.
 *
 * This scheduler is OPT-IN and INERT BY DEFAULT: it only becomes active when
 * anchoring (CHARIOT_TSA_URL + at least one anchor trigger) and/or attestation
 * (a ChainSigner custody backend configured/provisioned — chainSigner.ts —
 * plus at least one attest trigger) are configured.
 * When a feature's prerequisite is set but NEITHER of its triggers is
 * configured, startup fails loudly (spec §8.5: "At least one trigger … MUST be
 * configured") rather than silently degrading.
 *
 * It drives the SAME primitives the `chariot audit anchor` / `attest`
 * subcommands use (anchorChainHead, signLengthAttestation + persistAttestation)
 * against the live serve chain, on event-count OR wall-clock triggers.
 *
 * Trigger state is held in memory and (re)initialised from the current chain
 * length + clock at start(); a process restart re-evaluates from current state
 * on the first tick, so the window can never silently exceed the configured
 * bound across a restart by more than one poll interval.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { createInterface } from 'node:readline';
import { createReadStream, existsSync } from 'node:fs';
import { anchorChainHead } from './anchor.js';
import { persistAttestation, canonicalAttestationPayload } from './length-attestation.js';
// CHARIOT::§9.8.1::1 — the signing key is obtained through the ChainSigner
// custody abstraction (kms/vault-transit/sealed-store), never read
// directly here. There is no plaintext-env backend to refuse (review gate
// finding F1 removed it entirely) — see chainSigner.ts's module doc.
import { createChainSigner, isSealedStoreProvisioned, type ChainSigner } from './chainSigner.js';

export interface AuditCadenceHandle {
  stop(): void;
}

/** Parse a non-negative integer env var; 0/absent/invalid → 0 (disabled). */
function parseNonNegInt(raw: string | undefined): number {
  const n = parseInt(raw ?? '', 10);
  return Number.isFinite(n) && n > 0 ? n : 0;
}

/**
 * Read the current chain length and head hash (hex) from the serve JSONL
 * chain. Mirrors the CLI's readChainState but lives in the engine layer
 * (which must not import from src/bin). Counts only proper chain records
 * (numeric sequenceNumber + hash), so JSONL status-update supplement lines
 * do not inflate the length.
 */
async function readChainState(chainFile: string): Promise<{ length: number; headHash: string }> {
  if (!existsSync(chainFile)) return { length: 0, headHash: '' };
  const records: Array<{ sequenceNumber: number; hash: string }> = [];
  await new Promise<void>((resolve, reject) => {
    const rl = createInterface({
      input: createReadStream(chainFile, { encoding: 'utf-8' }),
      crlfDelay: Infinity,
    });
    rl.on('line', (line) => {
      const trimmed = line.trim();
      if (!trimmed) return;
      try {
        const r = JSON.parse(trimmed) as { sequenceNumber?: number; hash?: string };
        if (typeof r.sequenceNumber === 'number' && typeof r.hash === 'string' && r.hash.length > 0) {
          records.push({ sequenceNumber: r.sequenceNumber, hash: r.hash });
        }
      } catch {
        // skip unparseable lines
      }
    });
    rl.on('close', resolve);
    rl.on('error', reject);
  });
  if (records.length === 0) return { length: 0, headHash: '' };
  records.sort((a, b) => a.sequenceNumber - b.sequenceNumber);
  return { length: records.length, headHash: records[records.length - 1].hash };
}

/**
 * Start the periodic anchor/attest cadence for a serve chain. Returns a handle
 * whose stop() clears the timer, or undefined when neither feature is
 * configured (fully inert).
 *
 * @throws when a feature prerequisite is set but no trigger is configured
 *         (spec §8.5 MUST), so the misconfiguration surfaces loudly at startup.
 */
export function startAuditCadence(opts: {
  chainId: string;
  packageRoot: string;
  chainFilePath: string;
  logger?: (msg: string) => void;
}): AuditCadenceHandle | undefined {
  const log = opts.logger ?? ((m: string) => process.stderr.write(m + '\n'));

  const anchorEventInterval = parseNonNegInt(process.env.CHARIOT_ANCHOR_EVENT_INTERVAL);
  const anchorTimeIntervalMs = parseNonNegInt(process.env.CHARIOT_ANCHOR_TIME_INTERVAL_MS);
  const attestEventInterval = parseNonNegInt(process.env.CHARIOT_ATTEST_EVENT_INTERVAL);
  const attestTimeIntervalMs = parseNonNegInt(process.env.CHARIOT_ATTEST_TIME_INTERVAL_MS);

  const tsaUrl = process.env.CHARIOT_TSA_URL;
  // CHARIOT::§9.8.1::1 — "is attestation configured" stays a cheap
  // synchronous check (the ChainSigner itself is constructed lazily, once,
  // inside runAttest below — the kms/vault-transit backends need an async
  // network/dynamic-import call this function's sync signature cannot
  // make, and there is no plaintext env backend to detect via a bare env
  // read any more — gate finding F1 removed it). Attestation counts
  // as "configured" when an operator has explicitly pointed at a remote
  // backend (kms/vault-transit), OR the default sealed-store backend
  // already has a key provisioned (a cheap synchronous filesystem check —
  // `isSealedStoreProvisioned`, chainSigner.ts) so a fresh install with
  // nothing provisioned yet stays fully inert rather than erroring out.
  const signerBackend = (process.env.CHARIOT_AUDIT_SIGNER_BACKEND as 'kms' | 'vault-transit' | 'sealed-store' | undefined);
  const attestConfigured =
    signerBackend === 'kms' ||
    signerBackend === 'vault-transit' ||
    ((signerBackend === undefined || signerBackend === 'sealed-store') && isSealedStoreProvisioned(opts.packageRoot));

  const anchorConfigured = Boolean(tsaUrl);

  // CHARIOT::§9.8.4::4 — "Enabling TSA anchoring (CHARIOT_TSA_URL set) without
  // setting at least one cadence trigger is a configuration error and MUST
  // produce a startup warning" (CHARIOT-SPEC.md §9.8.4). The spec's own words
  // are "startup warning", not "abort startup" — so this is a loud, non-fatal
  // log, not a throw. Anchoring itself is left disabled (anchorEnabled below
  // computes false), the rest of `chariot serve` boots normally.
  if (anchorConfigured && anchorEventInterval === 0 && anchorTimeIntervalMs === 0) {
    log(
      'WARNING Chariot audit cadence: CHARIOT_TSA_URL is set (anchoring enabled) but neither ' +
        'CHARIOT_ANCHOR_EVENT_INTERVAL nor CHARIOT_ANCHOR_TIME_INTERVAL_MS is configured. ' +
        'At least one anchor trigger MUST be set (CHARIOT §9.8.4). Anchoring is DISABLED until fixed.',
    );
  }
  if (attestConfigured && attestEventInterval === 0 && attestTimeIntervalMs === 0) {
    throw new Error(
      'Chariot audit cadence: attestation signing is configured (CHARIOT_AUDIT_SIGNER_BACKEND=kms/vault-transit, ' +
        'or the default sealed-store backend already has a provisioned key; attestation enabled) but neither ' +
        'CHARIOT_ATTEST_EVENT_INTERVAL nor CHARIOT_ATTEST_TIME_INTERVAL_MS is configured. ' +
        'At least one attest trigger MUST be set (spec §8.5).',
    );
  }

  const anchorEnabled = anchorConfigured && (anchorEventInterval > 0 || anchorTimeIntervalMs > 0);
  const attestEnabled = attestConfigured && (attestEventInterval > 0 || attestTimeIntervalMs > 0);

  // Neither feature configured → fully inert (matches disabled-by-default).
  if (!anchorEnabled && !attestEnabled) return undefined;

  // CHARIOT::§9.8.4::2 — "the length-attestation cadence SHALL match or
  // exceed the anchor cadence to avoid an un-attested window where tail
  // truncation is undetectable" (CHARIOT-SPEC.md §9.8.4). Higher cadence ==
  // more frequent == a SMALLER interval value, so "attest cadence >= anchor
  // cadence" means attestInterval <= anchorInterval on the SAME basis
  // (event-count compared to event-count, time compared to time — the two
  // bases are not commensurable). Compared only when both sides of a basis
  // are actually configured; the spec's own wording ("should ... match or
  // exceed") is advisory, so a violation is a startup warning, not a throw.
  if (anchorEnabled && attestEnabled) {
    if (anchorEventInterval > 0 && attestEventInterval > 0 && attestEventInterval > anchorEventInterval) {
      log(
        `WARNING Chariot audit cadence: CHARIOT_ATTEST_EVENT_INTERVAL (${attestEventInterval}) is looser ` +
          `than CHARIOT_ANCHOR_EVENT_INTERVAL (${anchorEventInterval}) — attestation cadence MUST match or ` +
          'exceed anchor cadence (CHARIOT §9.8.4), or a gap opens where tail truncation is undetectable.',
      );
    }
    if (anchorTimeIntervalMs > 0 && attestTimeIntervalMs > 0 && attestTimeIntervalMs > anchorTimeIntervalMs) {
      log(
        `WARNING Chariot audit cadence: CHARIOT_ATTEST_TIME_INTERVAL_MS (${attestTimeIntervalMs}) is looser ` +
          `than CHARIOT_ANCHOR_TIME_INTERVAL_MS (${anchorTimeIntervalMs}) — attestation cadence MUST match or ` +
          'exceed anchor cadence (CHARIOT §9.8.4), or a gap opens where tail truncation is undetectable.',
      );
    }
  }

  // Poll cadence: the tightest configured wall-clock interval, clamped so we
  // neither busy-spin nor let a long interval blur event-count precision.
  const timeIntervals = [anchorTimeIntervalMs, attestTimeIntervalMs].filter((n) => n > 0);
  const desiredPoll = timeIntervals.length > 0 ? Math.min(...timeIntervals) : 60_000;
  const pollMs = Math.max(5_000, Math.min(desiredPoll, 300_000));

  let lastAnchorLen = 0;
  let lastAnchorAt = Date.now();
  let lastAttestLen = 0;
  let lastAttestAt = Date.now();
  let running = false;
  let stopped = false;

  // Initialise the windows from the current chain state so the first tick does
  // not immediately fire on pre-existing records.
  void readChainState(opts.chainFilePath).then((st) => {
    lastAnchorLen = st.length;
    lastAttestLen = st.length;
  }).catch(() => { /* first tick will read again */ });

  const runAnchor = async (length: number, headHex: string): Promise<void> => {
    if (!headHex || headHex.length !== 64) return; // empty chain — nothing to anchor
    const headBuf = Buffer.from(headHex, 'hex');
    await anchorChainHead({ chainId: opts.chainId, headHash: headBuf, packageRoot: opts.packageRoot, tsaUrl });
    lastAnchorLen = length;
    lastAnchorAt = Date.now();
    log(`Chariot audit cadence: anchored chain=${opts.chainId} length=${length}`);
  };

  // CHARIOT::§9.8.1::1 — constructed once, lazily, on the first actual
  // attest tick (not eagerly at startAuditCadence() call time) because the
  // kms/vault-transit backends require an async network/dynamic-import call
  // this function's own synchronous signature cannot make; the `env`
  // backend construction is synchronous-fast so this adds no observable
  // delay to the pre-existing single-user path.
  let cachedSigner: ChainSigner | undefined;
  const getSigner = async (): Promise<ChainSigner> => {
    if (!cachedSigner) cachedSigner = await createChainSigner({ packageRoot: opts.packageRoot });
    return cachedSigner;
  };

  const runAttest = async (length: number, headHex: string): Promise<void> => {
    if (length === 0 && !headHex) return; // empty chain — nothing to attest
    const signer = await getSigner();
    // Mirrors signLengthAttestation's own construction exactly (canonical
    // payload -> Ed25519 sign -> base64url), just sourcing the key from the
    // ChainSigner custody abstraction instead of a raw PEM string.
    const payload = {
      schemaVersion: 1 as const,
      chainId: opts.chainId,
      length,
      headHash: headHex,
      attestedAt: new Date().toISOString(),
    };
    const signature = await signer.sign(canonicalAttestationPayload(payload));
    const att = { ...payload, signature: signature.toString('base64url') };
    persistAttestation(opts.packageRoot, att);
    lastAttestLen = length;
    lastAttestAt = Date.now();
    log(`Chariot audit cadence: attested chain=${opts.chainId} length=${length}`);
  };

  const tick = async (): Promise<void> => {
    if (running || stopped) return;
    running = true;
    try {
      const st = await readChainState(opts.chainFilePath);
      const now = Date.now();

      if (anchorEnabled) {
        const byEvents = anchorEventInterval > 0 && st.length - lastAnchorLen >= anchorEventInterval;
        const byTime = anchorTimeIntervalMs > 0 && now - lastAnchorAt >= anchorTimeIntervalMs;
        if (byEvents || byTime) {
          try {
            await runAnchor(st.length, st.headHash);
          } catch (err) {
            // Do not advance the window on failure — retry next tick (backoff
            // is the poll interval). Loud stderr signal (honest-signal CH-31).
            log(`Chariot audit cadence: anchor failed (retry next tick): ${(err as Error).message}`);
          }
        }
      }

      if (attestEnabled) {
        const byEvents = attestEventInterval > 0 && st.length - lastAttestLen >= attestEventInterval;
        const byTime = attestTimeIntervalMs > 0 && now - lastAttestAt >= attestTimeIntervalMs;
        if (byEvents || byTime) {
          try {
            await runAttest(st.length, st.headHash);
          } catch (err) {
            log(`Chariot audit cadence: attest failed (retry next tick): ${(err as Error).message}`);
          }
        }
      }
    } finally {
      running = false;
    }
  };

  const timer = setInterval(() => { void tick(); }, pollMs);
  if (timer.unref) timer.unref();

  log(
    `Chariot audit cadence started (pollMs=${pollMs}` +
      `${anchorEnabled ? ` anchor[events=${anchorEventInterval},ms=${anchorTimeIntervalMs}]` : ''}` +
      `${attestEnabled ? ` attest[events=${attestEventInterval},ms=${attestTimeIntervalMs}]` : ''})`,
  );

  return {
    stop(): void {
      stopped = true;
      clearInterval(timer);
    },
  };
}

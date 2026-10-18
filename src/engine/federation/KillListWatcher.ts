/**
 * @epicai/chariot — Kill List Watcher (since 1.4.0)
 *
 * @deprecated since 3.0.0. The upstream catalog publisher's kill-list
 * artifact was retired in v1.2.0 of the publisher spec; the runtime
 * counterpart watcher in this file is therefore consuming a feed that
 * is no longer produced by the canonical Chariot catalog source. The
 * class remains exported for downstream SDK consumers who maintain
 * their own kill-list endpoint, and the bundled Chariot runtime can
 * construct and start this watcher when `CHARIOT_KILL_LIST_URL` is
 * configured. Catalog-refresh driven revocation
 * (`AdapterCatalogEntry.revoked = true`) plus `TenantDemotionOverrides`
 * for per-tenant overrides cover the same win condition, but they still
 * wait for the catalog refresh cadence. This watcher is the faster
 * revocation path: it polls a signed kill-list feed, diffs against the
 * currently connected adapters, and unloads newly revoked ones without
 * waiting for the full catalog refresh cycle.
 *
 * Polls a signed kill list from a well-known URL and calls
 * `FederationManager.unloadAdapter()` for any currently-connected
 * adapter whose `adapter_id` appears in the list. The kill list is
 * the runtime counterpart to the catalog revocation flag: a catalog
 * can take effect on the next release cycle, but a kill list takes
 * effect within one poll interval (default 5 minutes) without
 * requiring a Chariot upgrade, a process restart, or a catalog refresh.
 *
 * ## Trust model
 *
 * The kill list is Ed25519-signed using the same key pattern as the
 * adapter catalog (L2). When `publicKeyPem` is not supplied, the
 * watcher verifies against every entry of the compiled-in
 * `CHARIOT_CATALOG_PUBLIC_KEYS` rotation set from
 * `src/engine/keys/chariot-catalog-public.ts` (a signature that validates
 * against ANY entry is accepted; the matched entry's `id` is logged), so
 * operators using the default Chariot trust root get kill-list
 * enforcement for free and a key rotation of the catalog publisher never
 * strands the kill list on the previous key.
 *
 * Consumers who want a distinct kill-list key pass `publicKeyPem` in
 * `KillListWatcherOptions`. Consumers who explicitly want to opt out
 * of kill-list verification set `verifySignature: false` and see a
 * startup warning; the watcher then accepts unsigned lists. This is
 * NOT recommended for production.
 *
 * ## Format
 *
 * ```json
 * {
 *   "version": "2026-04-11-001",
 *   "generatedAt": "2026-04-11T12:00:00Z",
 *   "entries": [
 *     {
 *       "adapter_id": "chainlink",
 *       "reason": "contradiction_detected",
 *       "ruleId": "FAB-CONTRADICTION-003",
 *       "demotedAt": "2026-04-11T11:58:42Z",
 *       "incidentUrl": "https://submit.epicai.co/incidents/inc_abc"
 *     }
 *   ]
 * }
 * ```
 *
 * Signature delivery: base64 Ed25519 signature of the raw response
 * bytes, in the `kill-list-signature` HTTP response header. Same
 * byte-for-byte semantics as the catalog-signature header (raw bytes,
 * not re-serialized JSON).
 *
 * ## Lifecycle
 *
 * The watcher is opt-in. Construct, then call `start()`. It polls on
 * the configured interval, fetches, verifies, diffs against currently
 * loaded adapters (via `serverNames()`), and issues unload events.
 * Failures during fetch or verification are logged but do not crash
 * the watcher or affect the currently-loaded adapter set. Call
 * `stop()` to cancel the timer.
 */

import { verify as cryptoVerify } from 'node:crypto';
import { createLogger } from '../logger.js';
import {
  CHARIOT_CATALOG_PUBLIC_KEYS,
  type ChariotCatalogPublicKey,
} from '../keys/chariot-catalog-public.js';
import type { FederationManager } from './FederationManager.js';
// CHARIOT::§16.1 Federation (rulings item 91/105/112(a)) — direct import,
// matching this repo's established pattern.
import { chariotEmitter } from '../../observability/emitter.js';

const log = createLogger('federation.killlist');

// ─── Types ───────────────────────────────────────────────────────────────

export interface KillListEntry {
  adapter_id: string;
  reason?: string;
  ruleId?: string;
  demotedAt?: string;
  incidentUrl?: string;
  /**
   * Optional affected-version pinning. When present, the kill list
   * entry only applies to specific semver version strings. Empty,
   * undefined, or `["*"]` means "all versions". This field is
   * reserved for L4/5 when the adapter catalog carries explicit
   * version info; 1.4.0 treats every entry as all-versions.
   */
  affectedVersions?: string[];
}

export interface SignedKillList {
  version: string;
  generatedAt: string;
  entries: KillListEntry[];
}

/** Result of `verifyKillListSignature`: which accepted key (if any) validated the body. */
export type KillListSignatureVerdict =
  | { valid: true; keyId: string }
  | { valid: false; keyId: null };

/**
 * Verify a kill-list body against an accepted-key set. The signature is
 * accepted iff it validates against ANY entry (same rule as the catalog
 * rotation set in `chariot-catalog-public.ts`); the matched entry's `id`
 * is returned for logging. Key MATERIAL decides, never the `id`. Throws
 * only on malformed key material, which callers log as `verify_error`.
 */
export function verifyKillListSignature(
  bodyBytes: Buffer,
  signatureBase64: string,
  acceptedKeys: ReadonlyArray<ChariotCatalogPublicKey>,
): KillListSignatureVerdict {
  const signature = Buffer.from(signatureBase64, 'base64');
  for (const key of acceptedKeys) {
    if (cryptoVerify(null, bodyBytes, key.pem, signature)) {
      return { valid: true, keyId: key.id };
    }
  }
  return { valid: false, keyId: null };
}

export interface KillListWatcherOptions {
  /**
   * Federation manager to issue unload events against. Required —
   * the watcher is purposeless without a federation to act on.
   */
  federation: FederationManager;
  /**
   * URL of the signed kill list. When this is not set, the watcher
   * does nothing (start() is a no-op). In production this is typically
   * `https://submit.epicai.co/killlist` or an equivalent private URL
   * served from the catalog publisher's transparency surface.
   */
  url?: string;
  /**
   * Poll interval in milliseconds. Default 5 minutes.
   */
  intervalMs?: number;
  /**
   * Verify the Ed25519 signature on every fetch. Defaults to `true`.
   * Setting to `false` opts out and emits a startup warning — this
   * is NOT recommended for production deployments.
   */
  verifySignature?: boolean;
  /**
   * PEM-encoded Ed25519 public key used to verify the kill list.
   * Defaults to the bundled Chariot catalog rotation set
   * (`CHARIOT_CATALOG_PUBLIC_KEYS`, every entry accepted). Pass a
   * distinct key if your deployment uses separate signing keys for
   * catalog vs kill list; a supplied key is then the ONLY key tried.
   */
  publicKeyPem?: string;
  /**
   * Max quiescence window (ms) to pass to `unloadAdapter()`. Default
   * 30 seconds. In-flight calls to a killed adapter are allowed up to
   * this window to complete naturally before the transport is closed.
   */
  maxQuiescenceMs?: number;
}

// ─── Watcher ─────────────────────────────────────────────────────────────

export class KillListWatcher {
  private readonly federation: FederationManager;
  private readonly url: string | undefined;
  private readonly intervalMs: number;
  private readonly verifyEnabled: boolean;
  private readonly acceptedKeys: ReadonlyArray<ChariotCatalogPublicKey>;
  private readonly maxQuiescenceMs: number;

  private timer: ReturnType<typeof setInterval> | null = null;
  private running = false;
  private inFlightPoll = false;

  constructor(opts: KillListWatcherOptions) {
    this.federation = opts.federation;
    this.url = opts.url;
    this.intervalMs = opts.intervalMs ?? 5 * 60 * 1000;
    this.verifyEnabled = opts.verifySignature !== false;
    this.acceptedKeys =
      opts.publicKeyPem !== undefined
        ? [{ id: 'caller-supplied', pem: opts.publicKeyPem }]
        : CHARIOT_CATALOG_PUBLIC_KEYS;
    this.maxQuiescenceMs = opts.maxQuiescenceMs ?? 30_000;

    if (!this.verifyEnabled) {
      log.warn(
        'kill_list_watcher.signature_verification_disabled ' +
          '— kill list verification is OPT-OUT in 1.4.0+. ' +
          'This watcher will accept unsigned or tampered kill lists. ' +
          'Set verifySignature: true (the default) to enable. ' +
          'This warning fires on every startup by design.',
      );
    }
  }

  /**
   * Start polling. No-op when `url` is not set. Idempotent —
   * calling start() twice in a row is the same as calling it once.
   *
   * Start/stop race safety: the interval callback AND the immediate
   * first poll both guard on `this.running`. If `stop()` is called
   * during the initial async fetch, subsequent ticks see `running:
   * false` and exit without polling, even if the timer was installed
   * after `stop()` executed `clearInterval(null)`. The timer itself
   * is also cleared defensively on every `stop()` call.
   */
  start(): void {
    if (this.running) return;
    if (!this.url) {
      log.info('kill_list_watcher.disabled_no_url');
      return;
    }
    this.running = true;

    log.info('kill_list_watcher.started', {
      url: this.url,
      intervalMs: this.intervalMs,
      verify: this.verifyEnabled,
      keyIds: this.verifyEnabled ? this.acceptedKeys.map((k) => k.id) : ['disabled'],
    });

    // Install the interval timer FIRST, then fire the immediate poll.
    // This ordering ensures stop() always has a timer reference to
    // clear even if the initial async poll is still in flight. The
    // interval callback and pollOnce both guard on `this.running`,
    // so a concurrent stop() → subsequent tick path correctly skips.
    this.timer = setInterval(() => {
      if (!this.running) return;
      void this.pollOnce();
    }, this.intervalMs);

    if (this.timer && typeof this.timer === 'object' && 'unref' in this.timer) {
      this.timer.unref();
    }

    // Fire an immediate poll so a newly-started watcher does not wait
    // a full interval before its first check. If stop() lands before
    // this poll completes, the pollOnce() guard below exits cleanly.
    void this.pollOnce();
  }

  /**
   * Stop polling. Idempotent. Safe to call on an already-stopped
   * watcher and safe to call during an in-flight poll — the pollOnce
   * guard ensures any subsequent tick after stop() is a no-op.
   */
  stop(): void {
    this.running = false;
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
      log.info('kill_list_watcher.stopped');
    }
  }

  /**
   * Force a single poll outside the normal interval. Used by tests
   * and by operators who want to issue an immediate check without
   * waiting for the next tick. Async — callers can await to see
   * unload completion.
   */
  async pollNow(): Promise<void> {
    await this.pollOnce();
  }

  // ── Internal ───────────────────────────────────────────────────────────

  private async pollOnce(): Promise<void> {
    if (!this.url) return;
    // NOTE: `this.running` is NOT checked here. The timer callback
    // checks it before calling pollOnce, so timer-driven polls
    // respect the stopped state. `pollNow()` is a direct caller that
    // explicitly wants a poll even when the watcher is not under a
    // running interval, so we must not short-circuit here.
    if (this.inFlightPoll) {
      log.debug('kill_list_watcher.skipped_overlapping');
      return;
    }
    this.inFlightPoll = true;

    try {
      const killList = await this.fetchAndVerify(this.url);
      if (!killList) return; // fetch/verify already logged

      // Check currently-connected adapters on EVERY poll. The kill
      // list is a continuous enforcement loop, not a one-shot
      // suppression. If an adapter reconnects between polls — which
      // can happen after a reconnect cycle, a credential rotation,
      // or an upstream catalog re-probe that temporarily removed the
      // entry — the watcher must unload it again on the next poll that sees
      // it connected while its id is still on the list.
      //
      // Because the filter keys on current connection state rather
      // than a memoized history, the watcher is safe to re-poll
      // the same list version indefinitely without doing redundant
      // work: if the adapter is already gone, the entry is skipped
      // naturally. Memoization would be an incorrect optimization.
      const connectedServers = new Set(this.federation.serverNames());
      const toUnload = killList.entries.filter((entry) =>
        connectedServers.has(entry.adapter_id),
      );

      if (toUnload.length === 0) {
        log.debug('kill_list_watcher.no_action', {
          version: killList.version,
          entries: killList.entries.length,
          connected: connectedServers.size,
        });
        return;
      }

      log.info('kill_list_watcher.acting', {
        version: killList.version,
        toUnload: toUnload.map((e) => e.adapter_id),
      });

      for (const entry of toUnload) {
        const reason = entry.reason ?? 'kill_list';
        const result = await this.federation.unloadAdapter(
          entry.adapter_id,
          `kill_list: ${reason}` + (entry.ruleId ? ` (${entry.ruleId})` : ''),
          // CHARIOT::§7.6::1/§7.6::4/§7.6::5 — every kill-list unload IS a
          // runtime revocation: join the in-memory revocation set, cancel
          // pending approvals, and emit federation.adapter.revoked.
          { maxQuiescenceMs: this.maxQuiescenceMs, revoked: true },
        );
        log.info('kill_list_watcher.unloaded', {
          adapterId: entry.adapter_id,
          reason,
          ruleId: entry.ruleId,
          success: result.success,
          quiescent: result.quiescent,
          inFlightAtClose: result.inFlightAtClose,
          durationMs: result.durationMs,
        });
        // CHARIOT::§16.1 Federation (CHARIOT-SPEC.md:1347, rulings item
        // 91/105/112(a)/121) — the kill list's own runtime retirement
        // path (ruling 112(a): this watcher is live, not dead code,
        // despite its module-level @deprecated note about the upstream
        // FEED being retired — a caller can still construct and start it
        // against a self-hosted kill-list endpoint). RENAMED from the
        // spec's original event name (ruling 121: that name collides
        // with a repo leak-denylist pattern for internal catalog-
        // lifecycle vocabulary) — semantics unchanged: an adapter the
        // kill list names is retired from the tenant's catalog. Fires on
        // every unload attempt regardless of `result.success` — the
        // retirement decision was made and acted on either way; a failed
        // teardown (quiescence timeout, transport-close error) is
        // reflected in `result.success` for the caller, not withheld
        // from this notification. Distinct from `adapter.revoked`
        // (FederationManager.ts, fired inside unloadAdapter itself for
        // EVERY `revoked: true` unload, kill-list or otherwise) — this
        // event is specifically the kill-list's own retirement semantic,
        // carrying `demotedAt` from the signed kill-list entry (that
        // FIELD name is unrelated vocabulary and is unaffected by the
        // rename — see the field's own doc comment above).
        chariotEmitter.send('adapter.retired', {
          severity: 'warning',
          data: {
            adapterId: entry.adapter_id,
            demotedAt: entry.demotedAt ?? null,
            reason,
            ruleId: entry.ruleId ?? null,
            success: result.success,
          },
        });
      }
    } catch (err) {
      log.error('kill_list_watcher.poll_failed', {
        error: err instanceof Error ? err.message : String(err),
        note: 'retaining current adapter set',
      });
    } finally {
      this.inFlightPoll = false;
    }
  }

  private async fetchAndVerify(url: string): Promise<SignedKillList | null> {
    const response = await fetch(url);
    if (!response.ok) {
      log.warn('kill_list_watcher.fetch_failed', { url, status: response.status });
      return null;
    }

    // Raw bytes for signature verification — same reason as the
    // catalog path: text decoding could normalize BOMs or line
    // endings and break byte-for-byte signing.
    const bodyArrayBuffer = await response.arrayBuffer();
    const bodyBytes = Buffer.from(bodyArrayBuffer);

    if (this.verifyEnabled) {
      const signature = response.headers.get('kill-list-signature');
      if (!signature) {
        log.error('kill_list_watcher.missing_signature_header', {
          url,
          note:
            'kill list refused — set verifySignature: false to opt out (not recommended)',
        });
        return null;
      }
      let verdict: KillListSignatureVerdict;
      try {
        verdict = verifyKillListSignature(bodyBytes, signature, this.acceptedKeys);
      } catch (err) {
        log.error('kill_list_watcher.verify_error', {
          url,
          error: err instanceof Error ? err.message : String(err),
        });
        return null;
      }
      if (!verdict.valid) {
        log.error('kill_list_watcher.signature_verification_failed', {
          url,
          keyIds: this.acceptedKeys.map((k) => k.id),
          note: 'kill list refused — either tampered or signed with a key outside the accepted set',
        });
        return null;
      }
      log.debug('kill_list_watcher.signature_verified', { url, keyId: verdict.keyId });
    }

    let parsed: SignedKillList;
    try {
      parsed = JSON.parse(bodyBytes.toString('utf-8')) as SignedKillList;
    } catch (err) {
      log.error('kill_list_watcher.parse_failed', {
        url,
        error: err instanceof Error ? err.message : String(err),
      });
      return null;
    }

    if (!parsed.version || !Array.isArray(parsed.entries)) {
      log.error('kill_list_watcher.invalid_shape', {
        url,
        note: 'expected {version: string, entries: KillListEntry[]}',
      });
      return null;
    }

    return parsed;
  }
}

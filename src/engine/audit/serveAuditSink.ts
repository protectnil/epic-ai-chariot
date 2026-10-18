/**
 * @epicai/chariot — Serve-path Audit Sink (CH-45)
 *
 * Wires the engine HashChain (via {@link AuditTrail}) into the `chariot serve`
 * / MCP dispatch boundary so that REAL tool dispatches produce tamper-evident
 * audit records out-of-box.
 *
 * Before CH-45 the AuditTrail was constructed ONLY by `EpicAI.create()` (the
 * orchestrator embedding path), which `chariot serve` never calls — so ~20
 * real dispatches during the 3.1.2 dogfood produced ZERO audit records,
 * `~/.epic-ai/audit/` was never created, and `chariot audit anchor` reported
 * "chain file not found or empty" while §19 still advertised the audit trail
 * as "Shipped". This module makes the engine-chain write live on the serve
 * path (§7.1 / §8.4.1 "every dispatch recorded before the result", §22.6
 * OPEN-GAP-1 fix locus).
 *
 * Design decisions:
 *  - ONE COMPLETE hash-chained record per dispatch (NOT a pending+update
 *    pair). The JSONL store is append-only and a status-update line carries no
 *    sequenceNumber/previousHash, which would break HashChain.verifyChain —
 *    and `audit verify-length` / `verify-anchor` / the §22.6 verifyChain
 *    certification gate all require a clean, fully-verifiable chain. The record
 *    is written AFTER the federation dispatch resolves (or throws) and BEFORE
 *    the CallResult is handed back to the MCP caller, satisfying the
 *    "recorded before the result is returned" contract.
 *  - Chain location: `${EPIC_AI_DIR}/audit/${chainId}.jsonl` where
 *    EPIC_AI_DIR = EPIC_AI_DIR_OVERRIDE ?? ~/.epic-ai and chainId defaults to
 *    `default`. This is the exact path/naming the `chariot audit` CLI reads
 *    the head hash from (see test/hash-chain-anchor.mjs CLI cases), so anchor
 *    / attest / verify-length operate on the populated chain out-of-box. We
 *    resolve EPIC_AI_DIR locally rather than importing src/cli/paths.ts — the
 *    engine layer must not depend on the cli layer.
 *  - Best-effort, NOT fail-closed: a disk error (EROFS/ENOSPC) emits a LOUD
 *    stderr warning but does not take down the gateway or fail the caller's
 *    dispatch. The dangerous 3.1.2 failure mode was SILENT zero records; a
 *    loud warning is the honest-signal posture (CH-31). Operators who require
 *    fail-closed audit gate it at the storage layer (read-only → restart).
 *  - Redaction: the record captures the dispatch identity (adapter, tool,
 *    tenant, time, outcome) and the ARG KEYS, but NOT raw argument values or
 *    response bodies — those routinely carry upstream secrets/PII and this
 *    chain is plaintext JSONL on the operator's disk. Set
 *    CHARIOT_AUDIT_FULL_PAYLOAD=1 to record full args + a content preview when
 *    an operator's compliance posture requires it.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { homedir } from 'node:os';
import { join } from 'node:path';
import { AuditTrail } from './AuditTrail.js';
import type { ActionRecord, CallOutcome, ErrorClass } from '../types/index.js';

/** Default chain id — matches the `chariot audit` CLI's `${chainId}.jsonl`. */
export const DEFAULT_CHAIN_ID = 'default';

/**
 * Opt-in fail-closed audit mode. When CHARIOT_AUDIT_FAIL_CLOSED=1:
 *  - configureServeAudit() init failure ABORTS startup (throws) instead of
 *    continuing with audit silently disabled;
 *  - recordDispatch() rethrows on any write failure (and throws when no trail
 *    is configured) so the caller withholds the tool result rather than
 *    returning an unaudited success.
 * Default (unset) preserves the best-effort honest-signal posture (CH-31).
 * Mandatory for regulated deployments (see DEPLOYMENT-REGULATED-ENVIRONMENTS).
 */
export function isAuditFailClosed(): boolean {
  return process.env.CHARIOT_AUDIT_FAIL_CLOSED === '1';
}

/** Thrown by recordDispatch in fail-closed mode when a dispatch cannot be recorded. */
export class AuditWriteError extends Error {
  readonly code = 'AUDIT_WRITE_FAILED';
  constructor(message: string) {
    super(message);
    this.name = 'AuditWriteError';
  }
}

let serveAuditTrail: AuditTrail | undefined;
let configured = false;

/** EPIC_AI_DIR resolution — mirrors src/cli/paths.ts WITHOUT importing it
 *  (engine must not depend on the cli layer). */
export function resolveEpicAiDir(): string {
  return process.env.EPIC_AI_DIR_OVERRIDE ?? join(homedir(), '.epic-ai');
}

/** Absolute path of the serve-path audit chain JSONL. */
export function resolveAuditChainPath(chainId: string = DEFAULT_CHAIN_ID): string {
  return join(resolveEpicAiDir(), 'audit', `${chainId}.jsonl`);
}

/**
 * Construct + init the serve-path AuditTrail. Idempotent — the first call wins;
 * later calls return the existing instance. Call once at `chariot serve`
 * startup (both stdio and --http paths) BEFORE binding transports so the chain
 * is ready for the first dispatch.
 *
 * Returns undefined when audit is explicitly disabled (CHARIOT_AUDIT_DISABLED).
 */
export async function configureServeAudit(opts: {
  chainPath?: string;
  integrity?: 'sha256-chain' | 'none';
} = {}): Promise<AuditTrail | undefined> {
  if (configured) return serveAuditTrail;
  configured = true;

  if (process.env.CHARIOT_AUDIT_DISABLED === '1') {
    // Contradictory config: cannot both require fail-closed audit AND disable
    // audit. Refuse to start rather than silently running unaudited.
    if (isAuditFailClosed()) {
      configured = false;
      throw new Error(
        'Chariot audit: CHARIOT_AUDIT_FAIL_CLOSED=1 and CHARIOT_AUDIT_DISABLED=1 are mutually ' +
          'exclusive — fail-closed audit cannot be satisfied while audit is disabled.',
      );
    }
    serveAuditTrail = undefined;
    return undefined;
  }

  const path = opts.chainPath ?? resolveAuditChainPath();
  try {
    const trail = new AuditTrail({
      store: 'append-only-log',
      path,
      integrity: opts.integrity ?? 'sha256-chain',
    });
    // Rehydrate sequenceNumber + lastHash from any existing chain so a restart
    // continues the same hash chain rather than forking a new genesis.
    await trail.init();
    serveAuditTrail = trail;
    return trail;
  } catch (e) {
    // FAIL-CLOSED: abort startup so the gateway never serves dispatches it
    // cannot record. Reset `configured` so a supervisor retry re-attempts init.
    if (isAuditFailClosed()) {
      configured = false;
      serveAuditTrail = undefined;
      throw new Error(
        `Chariot audit (fail-closed): failed to initialise serve audit chain at ${path}: ` +
          `${(e as Error).message}. Refusing to start the gateway without a working audit chain.`,
      );
    }
    process.stderr.write(
      `Chariot audit: failed to initialise serve audit chain at ${path}: ` +
        `${(e as Error).message}. Tool dispatches will NOT be recorded until ` +
        `this is resolved (check that the directory is writable).\n`,
    );
    serveAuditTrail = undefined;
    return undefined;
  }
}

/** The configured serve AuditTrail, or undefined when unconfigured/disabled. */
export function getServeAuditTrail(): AuditTrail | undefined {
  return serveAuditTrail;
}

export interface DispatchAuditParams {
  adapterId: string;
  toolName: string;
  /** Raw tool args — only the KEYS are recorded unless CHARIOT_AUDIT_FULL_PAYLOAD=1. */
  args: Record<string, unknown>;
  tenantId: string;
  status: 'completed' | 'failed';
  outcome?: CallOutcome;
  errorClass?: ErrorClass;
  durationMs: number;
  /** Optional content preview length, recorded under output.contentBytes. */
  contentBytes?: number;
  retryCount?: number;
  retryReasons?: string[];
  /** Authenticated principal that initiated the dispatch, when known (JWT/enterprise auth). */
  userId?: string;
  /** Client IP the request originated from, when known (REST/HTTP transports). */
  sourceIp?: string;
}

/**
 * Record a single completed/failed dispatch into the hash chain. Awaited by
 * the dispatch wrapper so the record exists BEFORE the result is returned.
 * Best-effort: a write failure warns loudly to stderr and resolves (never
 * throws) so an audit-storage hiccup cannot break a customer dispatch.
 */
export async function recordDispatch(params: DispatchAuditParams): Promise<void> {
  const trail = serveAuditTrail;
  if (!trail) {
    // FAIL-CLOSED: no audit chain configured but audit is required — refuse to
    // let the dispatch result be returned unrecorded.
    if (isAuditFailClosed()) {
      throw new AuditWriteError(
        `audit required (CHARIOT_AUDIT_FAIL_CLOSED=1) but no audit chain is configured; ` +
          `refusing to return dispatch ${params.adapterId}:${params.toolName} unrecorded`,
      );
    }
    return;
  }

  const fullPayload = process.env.CHARIOT_AUDIT_FULL_PAYLOAD === '1';
  const input: Record<string, unknown> = fullPayload
    ? { args: params.args }
    : { argKeys: Object.keys(params.args ?? {}) };
  const output: Record<string, unknown> = {
    isError: params.status === 'failed',
    ...(params.outcome !== undefined ? { outcome: params.outcome } : {}),
    ...(params.contentBytes !== undefined ? { contentBytes: params.contentBytes } : {}),
  };

  const record: Omit<ActionRecord, 'id' | 'sequenceNumber' | 'previousHash' | 'hash'> = {
    timestamp: new Date(),
    action: 'chariot_call',
    tool: params.toolName,
    server: params.adapterId,
    // Direct MCP dispatch runs at the 'auto' autonomy tier — there is no
    // escalate/approve gate on chariot_call itself.
    tier: 'auto',
    status: params.status,
    input,
    output,
    // No persona engine on the serve path; the acting principal is the tenant.
    persona: params.tenantId,
    durationMs: params.durationMs,
    ...(params.outcome !== undefined ? { outcome: params.outcome } : {}),
    ...(params.errorClass !== undefined ? { errorClass: params.errorClass } : {}),
    ...(params.retryCount !== undefined ? { retryCount: params.retryCount } : {}),
    ...(params.retryReasons !== undefined ? { retryReasons: params.retryReasons } : {}),
    // Attribution: thread the authenticated principal + client
    // IP from the dispatch context so serve-path ActionRecords carry the same
    // who/where fields the orchestrator-embedding path (EpicAI.run/stream)
    // records. Absent when the transport genuinely has neither (e.g. stdio /
    // shared-bearer loopback) — never fabricated.
    ...(params.userId !== undefined ? { userId: params.userId } : {}),
    ...(params.sourceIp !== undefined ? { sourceIp: params.sourceIp } : {}),
  };

  try {
    await trail.record(record);
  } catch (e) {
    // FAIL-CLOSED: rethrow so the caller withholds the dispatch result rather
    // than returning an unaudited success. NOTE: the record is written AFTER
    // the dispatch resolves, so fail-closed withholds the RESULT and halts the
    // caller — it cannot un-execute the failing call's side effects.
    if (isAuditFailClosed()) {
      throw new AuditWriteError(
        `failed to record dispatch ${params.adapterId}:${params.toolName}: ${(e as Error).message}`,
      );
    }
    process.stderr.write(
      `Chariot audit: failed to record dispatch ${params.adapterId}:${params.toolName} ` +
        `(${(e as Error).message}). The dispatch result is still returned; the audit ` +
        `chain is MISSING this record.\n`,
    );
  }
}

/** Test-only reset of the module singleton. */
export function __resetServeAudit(): void {
  serveAuditTrail = undefined;
  configured = false;
}

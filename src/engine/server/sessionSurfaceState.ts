/**
 * @epicai/chariot — Session-scoped tool-surface tracker.
 *
 * Per-MCP-session memory of which (adapter, tool) tuples chariot_query has
 * surfaced to the calling agent. Used by handleCallImpl to fail-closed when
 * the agent invokes chariot_call on a tool it never received from a
 * chariot_query response in this session.
 *
 * Why this exists: chariot_call already validates that (adapter, tool) is
 * registered in the catalog (TOOL_NOT_REGISTERED), but an agent that knows
 * the catalog from prior context can still call a real adapter+tool that
 * was never surfaced as relevant to the current user query. This module
 * adds the missing guard — the agent must call chariot_query first, and
 * only the tuples that query surfaced are dispatchable in that session.
 *
 * Scope: enforced only when a sessionId is available. HTTP MCP transport
 * runs the SDK in stateless mode (sessionIdGenerator: undefined) for
 * partner-interop with browser-origin clients that do not echo
 * Mcp-Session-Id; the transport instead derives a per-request synthetic
 * session id from the access-token's `jti` claim (verified against
 * ENTERPRISE_JWT_SECRET) and exposes it via sessionContext
 * AsyncLocalStorage. stdio synthesises a stable per-process id; REST is
 * sessionless and bypasses the gate. Single-user `npx @epicai/chariot`
 * stdio installs still get protection because the stdio fallback id is
 * stable across the process lifetime, so chariot_query at the start of a
 * conversation surfaces tools for the rest of that session. Networked
 * HTTP installs get per-OAuth-grant protection because every chariot_call
 * carries the same jti as the chariot_query that surfaced its tuples.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

export type SessionId = string;

/** Composite key form `adapterId + ':' + toolName`. */
export type SurfacedKey = string;

export interface SurfacedToolTuple {
  adapterId: string;
  toolName: string;
  /** The query that surfaced this tuple (informational, for telemetry). */
  query: string;
  /** retrievalConfidence at the time of surfacing (informational). */
  retrievalConfidence: number;
  /** Wall-clock ms when the tuple was first surfaced in this session. */
  surfacedAtMs: number;
}

export interface SessionSurfaceState {
  /**
   * Outer key: sessionId. Inner key: `${adapterId}:${toolName}`.
   * Inner value preserves first-surfacing metadata (no overwrite on
   * subsequent surfacings, so telemetry shows when the agent first saw
   * the tuple in the conversation).
   */
  surfacedBySession: Map<SessionId, Map<SurfacedKey, SurfacedToolTuple>>;
}

export function createSessionSurfaceState(): SessionSurfaceState {
  return { surfacedBySession: new Map() };
}

export function composeSurfacedKey(adapterId: string, toolName: string): SurfacedKey {
  return `${adapterId}:${toolName}`;
}

/**
 * Record every (adapterId, toolName) pair returned in a chariot_query
 * matched response under the given session. Idempotent: re-recording an
 * already-surfaced tuple is a no-op (the existing surfacedAtMs is kept).
 */
export function recordSurfacedTuples(
  state: SessionSurfaceState,
  sessionId: SessionId,
  query: string,
  retrievalConfidence: number,
  tuples: ReadonlyArray<{ adapterId: string; toolName: string }>,
): void {
  let bucket = state.surfacedBySession.get(sessionId);
  if (!bucket) {
    bucket = new Map();
    state.surfacedBySession.set(sessionId, bucket);
  }
  const now = Date.now();
  for (const { adapterId, toolName } of tuples) {
    const key = composeSurfacedKey(adapterId, toolName);
    if (!bucket.has(key)) {
      bucket.set(key, {
        adapterId,
        toolName,
        query,
        retrievalConfidence,
        surfacedAtMs: now,
      });
    }
  }
}

/**
 * Return true when the given (adapter, tool) was surfaced to this session
 * by some prior chariot_query. Sessions with no prior surfacing return
 * false (the gate must fail-closed).
 */
export function wasSurfacedInSession(
  state: SessionSurfaceState,
  sessionId: SessionId,
  adapterId: string,
  toolName: string,
): boolean {
  const bucket = state.surfacedBySession.get(sessionId);
  if (!bucket) return false;
  return bucket.has(composeSurfacedKey(adapterId, toolName));
}

/**
 * Test/teardown helper: drop a session's surface state. Production code
 * does not need this on the success path — sessions are kept until the
 * process exits — but a session id reset on disconnect could call it.
 */
export function clearSession(state: SessionSurfaceState, sessionId: SessionId): void {
  state.surfacedBySession.delete(sessionId);
}

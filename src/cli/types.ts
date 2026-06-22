/**
 * @epicai/chariot — Shared CLI Types
 * Shapes used by both the outer Chariot CLI and the bundled engine setup CLI.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

export interface AdapterState {
  schemaVersion: number;
  lastHealthCheck: string | null;
  adapters: Record<string, {
    type: string;
    status: string;
    toolCount: number;
    installedVersion?: string;
    lastVerified: string | null;
    /**
     * ISO-8601 timestamp the operator interactively approved this CLI
     * adapter via `chariot approve <id>` per AS §1.5. Absent (undefined
     * or null) means unapproved — the dispatcher refuses CLI tool calls
     * with errorCode `CLI_APPROVAL_REQUIRED`. CLI adapters only;
     * ignored for STDIO/streamable-http/REST.
     */
    approvedAt?: string | null;
    /**
     * Snapshot of the binary path + argv template the operator saw at
     * approval time, hashed (SHA-256 hex). The dispatcher recomputes
     * this on every CLI tool call and refuses (CLI_APPROVAL_REQUIRED)
     * when the current adapter shape differs — closes the TOCTOU
     * where a binary is replaced or argv template is mutated between
     * approval and dispatch.
     */
    approvedShapeHash?: string | null;
    /**
     * In-flight transaction marker for the 2PC approve/revoke protocol
     * (review-prescribed 2026-05-25). Present ONLY between the audit
     * `*_intent` row and its `*_committed` / `*_failed` terminator.
     * `loadState()` invokes `reconcilePendingApprovals()` on every parse
     * to walk the audit chain and either finalize the approval (if
     * committed) or clear `approvalTx` (if failed / no terminator).
     * The dispatcher trusts ONLY `approvedAt` / `approvedShapeHash` —
     * `approvalTx` alone never authorises a CLI tool call.
     */
    approvalTx?: {
      id: string;
      kind: 'approve' | 'revoke';
      startedAt: string;
      shapeHash: string | null;
    } | null;
  }>;
}

export interface ChariotConfig {
  selectedAdapters: string[];
  secretsProvider: string;
  aiClient: string;
  localBackend?: string;
}

export interface McpClientInfo {
  id: string;
  name: string;
  detected: boolean;
  configPath: string;
  configKey: string;
  hint?: string;
}

export interface SystemInfo {
  nodeVersion: string;
  platform: string;
  arch: string;
  localPort: number | null;
  localBackend: string | null;
  mcpClients: McpClientInfo[];
}

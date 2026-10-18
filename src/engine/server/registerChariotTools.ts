/**
 * @epicai/chariot — Register Chariot Tools
 * Registers the three MCP tools on a McpServer instance.
 * Pure function — no I/O, no transport binding.
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { ChariotState } from './ChariotState.js';
import { handleQuery, handleCall, handleList, credentialPrompterStorage } from './toolHandlers.js';
import { createCredentialPrompter } from '../credentials/credentialPrompter.js';

// C4AMD::§2::1 — Chariot's client-visible MCP tool surface is exactly these
// three tools (chariot_query, chariot_call, chariot_list) per C4AMD §2 and
// CHARIOT-SPEC §17.3/§22.2. chariot_remember, chariot_resolve_entity,
// chariot_recall, chariot_compare_entities, chariot_forget,
// chariot_entity_profile, and chariot_validate_claim were previously
// registered here unconditionally; neither clause admits a conditional home
// for them on the MCP surface, so they are NOT registered here. The memory
// and entity handlers (memoryHandlers.ts, entity/handlers.ts) were deleted on
// 2026-09-03 (rulings item 73, C4AMD::§2::1 — exactly three client-visible
// tools); handleValidateClaim remains in toolHandlers.ts because it is
// dispatched from the HTTP REST surface at transports/rest.ts:325.
export const CLIENT_VISIBLE_TOOL_NAMES = ['chariot_query', 'chariot_call', 'chariot_list'] as const;

// cap every string arg at the same length so JSON error payloads can
// never serialize a multi-megabyte attacker-controlled string. One constant so
// the limit stays consistent if tuned.
const MAX_ARG_LEN = 256;
// Natural-language searches need more room than identifiers and filters.
// Keep the tighter cap for adapter/tool/category/search arguments while
// allowing the model to preserve a complete user request in chariot_query.
const MAX_QUERY_LEN = 1024;

/**
 * Per-instance security context for a registered McpServer.
 * Each McpServer is built per-request on the streamable-HTTP path and
 * per-process on stdio, so a single context per registration is enough.
 *
 * - HTTP (verified JWT): tenantId + auth from the token, localMode:false →
 *   handleCall enforces per-operation RBAC (deny-by-default) and every tool
 *   reads the caller's own tenant.
 * - stdio / shared-bearer loopback: localMode:true with the process tenant —
 *   the single local operator (or shared-secret loopback) is implicitly
 *   trusted; there is no cross-tenant surface to isolate.
 */
export interface ChariotToolSecurityContext {
  /** Caller's verified tenant (per-request on HTTP; process tenant on stdio/loopback). */
  tenantId: string;
  /** RBAC grants from the verified session; undefined → anonymous (deny-by-default unless localMode). */
  auth?: { allowedOperations?: Record<string, string[]>; userId: string; isAdmin?: boolean };
  /** Single-user trust opt-in (stdio / shared-bearer loopback). NEVER true on the multi-tenant JWT path. */
  localMode: boolean;
  /**
   * Stable session id used when the MCP SDK does not surface one via
   * RequestHandlerExtra. Streamable-HTTP populates extra.sessionId from the
   * transport's sessionIdGenerator (undefined in our stateless mode, so the
   * JWT jti is used); stdio passes a per-process synthesised id. When neither
   * source produces an id, the session-surface gate in handleCallImpl is
   * bypassed for that call (sessionless transport path).
   */
  sessionId?: string;
  /**
   * Verified JWT jti for the authenticated session (HTTP/JWT path only).
   * Threaded into handleCall as `sessionJti` so the ID-JAG per-user
   * subject-token exchange in handleCallInner fires for /mcp the same way it
   * does for REST (transports/rest.ts:callContextFromRequest). Absent on
   * stdio / shared-bearer loopback (no per-user downstream credential path).
   */
  sessionJti?: string;
  /**
   * Client IP the request originated from, when the transport can determine
   * one (streamable-HTTP — from the request socket). Threaded into
   * handleCall's CallContext so the serve-path audit record (recordDispatch)
   * carries it. Undefined on stdio (no per-request network origin) — never
   * fabricated.
   */
  sourceIp?: string;
}

export function registerChariotTools(
  server: McpServer,
  state: ChariotState,
  sec: ChariotToolSecurityContext,
): void {
  // chariot_query — natural language search over configured or full-catalog adapters
  server.tool(
    'chariot_query',
    'Natural language search over your configured adapters (or the full bundled ' +
      'catalog with discover:true) that ranks and returns matching adapters and ' +
      'their tools, for use as input to chariot_call.',
    {
      query: z.string().max(MAX_QUERY_LEN).describe(
        'Natural language query. PRESERVE concrete signals from the user\'s ' +
          'request when rephrasing: error states (5xx, crash, failure), metric ' +
          'types (rate, p99, latency, count), and time windows (last hour, ' +
          'yesterday, Q4). Do NOT collapse these into generic terms like ' +
          '"monitoring" — they steer routing toward the right adapter ' +
          '(observability vs CI/CD vs analytics). Searches your configured ' +
          'adapters by default. Keep the query at or below 1,024 characters; ' +
          'if the request is longer, summarize it while preserving those ' +
          'concrete signals. Use discover:true to search the full bundled catalog.',
      ),
      detail: z.enum(['full', 'summary']).optional().describe(
        'full (default): top 20 with tool lists. summary: one-line adapter summaries — use this when the first call missed.',
      ),
      discover: z.boolean().optional().describe(
        'Set to true to search ALL available adapters, not just your configured ones.',
      ),
    },
    async (args, extra) => {
      // Session id from the MCP SDK RequestHandlerExtra surfaces the
      // streamable-http transport's per-session uuid (and the stdio
      // fallback we synthesise in setup.ts). Threading it into handleQuery
      // lets the session-surface tracker record which tuples were
      // surfaced to this conversation. Casting via unknown because
      // RequestHandlerExtra typings vary across SDK minor versions.
      const sessionId = (extra as unknown as { sessionId?: string } | undefined)?.sessionId ?? sec.sessionId;
      // Thread the caller's verified tenant so the query-side
      // adapter inventory and per-tenant context budget are tenant-isolated.
      // Tenant is session/process-configured, never from tool args.
      // CHARIOT::§16.2 step 4 (rulings item 91(2)/115) — isAdmin threaded
      // from the verified session only (sec.auth), never from `args`.
      const result = await handleQuery(args, state, { sessionId, tenantId: sec.tenantId, isAdmin: sec.auth?.isAdmin });
 // surface query-side isError + estimatedTokenCost via the
      // MCP envelope so callers see budget-exceeded as a tool error and
      // can read the context-cost contribution as _meta.
      const isError = typeof result === 'object' && result !== null && (result as { isError?: boolean }).isError === true;
      const tokenCost = typeof result === 'object' && result !== null ? (result as { estimatedTokenCost?: number }).estimatedTokenCost : undefined;
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(result) }],
        ...(isError ? { isError: true } : {}),
        ...(tokenCost !== undefined ? { _meta: { estimatedTokenCost: tokenCost } } : {}),
      };
    },
  );

  // Out-of-band credential entry (the AI is the interface; the model never sees
  // a secret). Created ONLY for the single-user local transport: in multi-tenant
  // HTTP (`localMode:false`) there is no private page to send a tenant to, and
  // tenant credentials go through the IAM vault, so no prompter exists there.
  const credentialPrompter = sec.localMode
    ? createCredentialPrompter({ server: server.server as unknown as Parameters<typeof createCredentialPrompter>[0]['server'] })
    : undefined;

  // chariot_call — execute a tool on a specific adapter
  server.tool(
    'chariot_call',
    'Execute a specific tool on a specific adapter that was returned by a prior ' +
      'chariot_query response. Do not invent adapter or tool names.',
    {
      adapter: z.string().max(MAX_ARG_LEN).describe(
        'Adapter ID returned by chariot_query in matchedAdapters[].id ' +
          '(e.g., "github", "crowdstrike", "salesforce"). Do NOT invent ' +
          'adapter IDs not present in a prior chariot_query response.',
      ),
      tool: z.string().max(MAX_ARG_LEN).describe(
        'Tool name to call on the adapter. MUST be a tool name that ' +
          'appears as matchedAdapters[adapter].tools[].name from a prior ' +
          'chariot_query response. Do NOT fabricate tool names based on ' +
          'the adapter description or your prior knowledge of the vendor ' +
          'API — only the names returned by chariot_query are guaranteed ' +
          'to dispatch. If chariot_query returned no tool that matches ' +
          'the user\'s request, tell the user the catalog has no tool ' +
          'for this task instead of guessing a plausible name.',
      ),
      args: z.record(z.string(), z.unknown()).optional().describe('Arguments to pass to the tool'),
    },
    async (toolArgs, extra) => {
      // Enforce per-operation RBAC + tenant isolation from the
      // verified per-request context (sec), not a hardcoded localMode:true.
      //   - HTTP / verified JWT: sec.localMode=false + sec.auth → handleCall
      //     enforces isOperationAllowed (deny-by-default) for sec.tenantId.
      //   - stdio / shared-bearer loopback: sec.localMode=true → the single
      //     local operator is the only caller and is implicitly trusted.
      // Tenant identity + RBAC scope always come from sec, never tool args.
      const sessionId = (extra as unknown as { sessionId?: string } | undefined)?.sessionId ?? sec.sessionId;
      const dispatch = () => handleCall(toolArgs, state, {
        tenantId: sec.tenantId,
        auth: sec.auth,
        localMode: sec.localMode,
        sessionId,
        // ID-JAG per-user subject-token exchange (REST parity, rest.ts:57):
        // present only on the verified JWT path; absent on stdio/loopback.
        ...(sec.sessionJti !== undefined ? { sessionJti: sec.sessionJti } : {}),
        // Client IP (REST parity, rest.ts:callContextFromRequest)
        // so the serve-path audit record carries sourceIp. Absent on stdio.
        ...(sec.sourceIp !== undefined ? { sourceIp: sec.sourceIp } : {}),
      });
      const result = credentialPrompter
        ? await credentialPrompterStorage.run(credentialPrompter, dispatch)
        : await dispatch();
 // surface estimatedTokenCost as MCP _meta so external
      // callers see the context-cost contribution. Without this, the new
      // metadata is dropped at the MCP boundary even though handleCall
      // stamps it on every CallResult.
      return {
        content: [{ type: 'text' as const, text: result.content }],
        isError: result.isError,
        ...(result.estimatedTokenCost !== undefined ? { _meta: { estimatedTokenCost: result.estimatedTokenCost } } : {}),
      };
    },
  );

  // chariot_list — browse available adapters by category or keyword
  server.tool(
    'chariot_list',
    'Browse the full bundled adapter catalog by category name or keyword, ' +
      'independent of which adapters are currently configured.',
    {
      category: z.string().max(MAX_ARG_LEN).optional().describe(
        'Filter by category name (e.g., "cybersecurity", "healthcare", "devops", "finance").',
      ),
      search: z.string().max(MAX_ARG_LEN).optional().describe('Search by keyword across adapter names and descriptions'),
    },
    async (args, extra) => {
      // chariot_list browses the global bundled catalog (state.allAdapters),
      // which carries no tenant-private data, so no per-request tenant
      // context is threaded here (query/call are the
      // tenant-keyed surfaces) — EXCEPT for the CHARIOT::§16.2 step 4
      // pendingAlerts gate (rulings item 91(2)/115), which DOES need
      // sessionId/tenantId/isAdmin, mirroring chariot_query's handler.
      const sessionId = (extra as unknown as { sessionId?: string } | undefined)?.sessionId ?? sec.sessionId;
      const result = await handleList(args, state, { sessionId, tenantId: sec.tenantId, isAdmin: sec.auth?.isAdmin });
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(result) }],
      };
    },
  );
}

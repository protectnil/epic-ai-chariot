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
import { handleRemember, handleRecall, handleForget } from './memoryHandlers.js';
import {
  handleResolveEntity,
  handleCompareEntities,
  handleEntityProfile,
} from '../entity/handlers.js';
import { handleQuery, handleCall, handleList, handleValidateClaim } from './toolHandlers.js';

// cap every string arg at the same length so JSON error payloads can
// never serialize a multi-megabyte attacker-controlled string. One constant so
// the limit stays consistent if tuned.
const MAX_ARG_LEN = 256;

/**
 * Per-instance security context for a registered McpServer (bug-tracker-ref).
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
  auth?: { allowedOperations?: Record<string, string[]>; userId: string };
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
}

export function registerChariotTools(
  server: McpServer,
  state: ChariotState,
  sec: ChariotToolSecurityContext,
): void {
  // chariot_query — natural language search over configured or full-catalog adapters
  server.tool(
    'chariot_query',
    {
      query: z.string().max(MAX_ARG_LEN).describe(
        'Natural language query. PRESERVE concrete signals from the user\'s ' +
          'request when rephrasing: error states (5xx, crash, failure), metric ' +
          'types (rate, p99, latency, count), and time windows (last hour, ' +
          'yesterday, Q4). Do NOT collapse these into generic terms like ' +
          '"monitoring" — they steer routing toward the right adapter ' +
          '(observability vs CI/CD vs analytics). Searches your configured ' +
          'adapters by default. Use discover:true to search the full bundled ' +
          'catalog.',
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
      // bug-tracker-ref: thread the caller's verified tenant so the query-side
      // adapter inventory and per-tenant context budget are tenant-isolated.
      // Tenant is session/process-configured, never from tool args.
      const result = await handleQuery(args, state, { sessionId, tenantId: sec.tenantId });
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

  // chariot_call — execute a tool on a specific adapter
  server.tool(
    'chariot_call',
    {
      adapter: z.string().max(MAX_ARG_LEN).describe(
        'Adapter ID returned by chariot_query in matchedAdapters[].id ' +
          '(e.g., "github", "crowdstrike", "salesforce"). Do NOT invent ' +
          'adapter IDs not present in a prior chariot_query response.',
      ),
      tool: z.string().max(MAX_ARG_LEN).describe(
        'Tool name to call on the adapter. MUST be a tool name that ' +
          'appears in matchedAdapters[adapter].tools from a prior ' +
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
      // bug-tracker-ref: enforce per-operation RBAC + tenant isolation from the
      // verified per-request context (sec), not a hardcoded localMode:true.
      //   - HTTP / verified JWT: sec.localMode=false + sec.auth → handleCall
      //     enforces isOperationAllowed (deny-by-default) for sec.tenantId.
      //   - stdio / shared-bearer loopback: sec.localMode=true → the single
      //     local operator is the only caller and is implicitly trusted.
      // Tenant identity + RBAC scope always come from sec, never tool args.
      const sessionId = (extra as unknown as { sessionId?: string } | undefined)?.sessionId ?? sec.sessionId;
      const result = await handleCall(toolArgs, state, {
        tenantId: sec.tenantId,
        auth: sec.auth,
        localMode: sec.localMode,
        sessionId,
        // ID-JAG per-user subject-token exchange (REST parity, rest.ts:57):
        // present only on the verified JWT path; absent on stdio/loopback.
        ...(sec.sessionJti !== undefined ? { sessionJti: sec.sessionJti } : {}),
      });
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
    {
      category: z.string().max(MAX_ARG_LEN).optional().describe(
        'Filter by category name (e.g., "cybersecurity", "healthcare", "devops", "finance").',
      ),
      search: z.string().max(MAX_ARG_LEN).optional().describe('Search by keyword across adapter names and descriptions'),
    },
    async (args) => {
      // chariot_list browses the global bundled catalog (state.allAdapters),
      // which carries no tenant-private data, so no per-request tenant
      // context is threaded here (bug-tracker-ref scope: query/call are the
      // tenant-keyed surfaces).
      const result = await handleList(args, state);
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(result) }],
      };
    },
  );

  // chariot_remember — store a memory for the current user
  // Tenant-scoped: memories are keyed on sec.tenantId so cross-tenant
  // isolation is the same as query/call. localMode uses the process tenant.
  server.tool(
    'chariot_remember',
    {
      content: z.string().max(4096).describe(
        'The information to remember. Be specific — vague strings reduce recall quality.',
      ),
      type: z.string().max(MAX_ARG_LEN).optional().describe(
        'Memory category tag (e.g., "preference", "fact", "instruction", "context"). ' +
          'Used to filter recall results by type. Defaults to "general".',
      ),
      importance: z.enum(['normal', 'medium', 'high']).optional().describe(
        'Importance tier. "high" persists through capacity eviction; ' +
          '"normal" (default) is evicted first when the store is full.',
      ),
    },
    async (args) => {
      const result = await handleRemember(args, state, sec.tenantId);
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(result) }],
        ...(result.isError ? { isError: true } : {}),
      };
    },
  );

  // -------------------------------------------------------------------------
  // Entity resolution tools.
  //
  // resolve_entity / compare_entities / entity_profile are engine-level
  // controls that federate entity intelligence across the full adapter
  // catalog via EntityResolver — no external gateway is required. They run
  // under the caller's RBAC/tenant context (sec is threaded into the handler).
  // -------------------------------------------------------------------------

  // chariot_resolve_entity — resolve an entity across the adapter catalog
  server.tool(
    'chariot_resolve_entity',
    {
      entity: z.string().max(MAX_ARG_LEN).describe(
        'Entity identifier or natural-language description to resolve (e.g. a username, ' +
          'hostname, package name, alert ID, or org name). The resolver fans out to every ' +
          'adapter in the catalog that exposes a search or lookup tool and returns ' +
          'aggregated evidence with a canonical display name and entity type.',
      ),
      adapterIds: z.array(z.string().max(MAX_ARG_LEN)).max(32).optional().describe(
        'Optional list of adapter IDs to restrict the resolution scope. ' +
          'When omitted the full catalog is searched (up to maxAdapters adapters).',
      ),
      maxAdapters: z.number().int().min(1).max(50).optional().describe(
        'Maximum number of adapters to probe in parallel (default 12). ' +
          'Increase only when a broader sweep is needed.',
      ),
    },
    async (args) => {
      const result = await handleResolveEntity(args, state, {
        tenantId: sec.tenantId,
        auth: sec.auth,
        localMode: sec.localMode,
        sessionId: sec.sessionId,
        ...(sec.sessionJti !== undefined ? { sessionJti: sec.sessionJti } : {}),
      });
      return {
        content: [{ type: 'text' as const, text: result.content }],
        isError: result.isError,
        ...(result.estimatedTokenCost !== undefined
          ? { _meta: { estimatedTokenCost: result.estimatedTokenCost } }
          : {}),
      };
    },
  );

  // chariot_recall — retrieve memories for the current user
  server.tool(
    'chariot_recall',
    {
      type: z.string().max(MAX_ARG_LEN).optional().describe(
        'Filter by memory type tag (must match the type used when storing). ' +
          'Omit to retrieve across all types.',
      ),
      importance: z.enum(['normal', 'medium', 'high']).optional().describe(
        'Filter to a specific importance tier. Omit to retrieve all tiers.',
      ),
      limit: z.number().int().min(1).max(100).optional().describe(
        'Maximum number of memories to return (default 10, max 100).',
      ),
      sortBy: z.enum(['importance', 'recency', 'frequency']).optional().describe(
        'Sort order: "recency" (newest first, default), "importance" (high → normal), ' +
          '"frequency" (most-accessed first).',
      ),
    },
    async (args) => {
      const result = await handleRecall(args, state, sec.tenantId);
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(result) }],
        ...(result.isError ? { isError: true } : {}),
      };
    },
  );

  // chariot_compare_entities — structural comparison of two entities
  server.tool(
    'chariot_compare_entities',
    {
      entityA: z.string().max(MAX_ARG_LEN).describe(
        'First entity identifier or description (e.g. username, hostname, package name).',
      ),
      entityB: z.string().max(MAX_ARG_LEN).describe(
        'Second entity identifier or description to compare against entityA.',
      ),
      adapterIds: z.array(z.string().max(MAX_ARG_LEN)).max(32).optional().describe(
        'Optional adapter scope for both resolutions. Same semantics as chariot_resolve_entity.adapterIds.',
      ),
      maxAdapters: z.number().int().min(1).max(50).optional().describe(
        'Maximum adapters to probe per entity (default 12).',
      ),
    },
    async (args) => {
      const result = await handleCompareEntities(args, state, {
        tenantId: sec.tenantId,
        auth: sec.auth,
        localMode: sec.localMode,
        sessionId: sec.sessionId,
        ...(sec.sessionJti !== undefined ? { sessionJti: sec.sessionJti } : {}),
      });
      return {
        content: [{ type: 'text' as const, text: result.content }],
        isError: result.isError,
        ...(result.estimatedTokenCost !== undefined
          ? { _meta: { estimatedTokenCost: result.estimatedTokenCost } }
          : {}),
      };
    },
  );

  // chariot_forget — soft-delete a memory by its id
  server.tool(
    'chariot_forget',
    {
      id: z.string().max(MAX_ARG_LEN).describe(
        'Memory id returned by chariot_remember or chariot_recall. ' +
          'MUST be an id from a prior chariot_recall response — do NOT invent ids.',
      ),
    },
    async (args) => {
      const result = await handleForget(args, state, sec.tenantId);
      return {
        content: [{ type: 'text' as const, text: JSON.stringify(result) }],
        ...(result.isError ? { isError: true } : {}),
      };
    },
  );

  // chariot_entity_profile — build a structured profile for an entity
  server.tool(
    'chariot_entity_profile',
    {
      entity: z.string().max(MAX_ARG_LEN).describe(
        'Entity identifier to profile (e.g. username, hostname, package name, alert ID). ' +
          'The profiler fans out across the catalog and aggregates all returned data into a ' +
          'flat attribute bag alongside raw per-adapter payloads.',
      ),
      adapterIds: z.array(z.string().max(MAX_ARG_LEN)).max(32).optional().describe(
        'Optional adapter scope. Same semantics as chariot_resolve_entity.adapterIds.',
      ),
      maxAdapters: z.number().int().min(1).max(50).optional().describe(
        'Maximum adapters to probe (default 12).',
      ),
    },
    async (args) => {
      const result = await handleEntityProfile(args, state, {
        tenantId: sec.tenantId,
        auth: sec.auth,
        localMode: sec.localMode,
        sessionId: sec.sessionId,
        ...(sec.sessionJti !== undefined ? { sessionJti: sec.sessionJti } : {}),
      });
      return {
        content: [{ type: 'text' as const, text: result.content }],
        isError: result.isError,
        ...(result.estimatedTokenCost !== undefined
          ? { _meta: { estimatedTokenCost: result.estimatedTokenCost } }
          : {}),
      };
    },
  );

  // chariot_validate_claim — engine-level claim-validation / data grounding.
  // Native engine claim-validation / data-grounding tool.
  // Evaluates whether caller-supplied evidence text supports, contradicts, or
  // is insufficient to assess a stated claim.  Callers typically pass a prior
  // chariot_call response as the evidence.  Uses an LLM when state.claimValidatorLlm
  // is configured; falls back to deterministic heuristic grounding otherwise.
  server.tool(
    'chariot_validate_claim',
    {
      claim: z.string().min(1).max(512).describe(
        'The assertion to validate (e.g., "Acme Corp is SOC-2 certified", ' +
          '"the server returned HTTP 200"). Must be a concrete, falsifiable statement. ' +
          'Do NOT pass a question — rephrase as a positive claim first.',
      ),
      evidence: z.string().max(8192).describe(
        'Text evidence to ground the claim against. Typically the content field ' +
          'from a prior chariot_call response. May also be any structured or ' +
          'unstructured text (JSON, prose, log lines). Pass an empty string when ' +
          'you have no evidence — the tool returns verdict:"no_evidence" in that case.',
      ),
    },
    async (args) => {
      const result = await handleValidateClaim(args, state, {
        tenantId: sec.tenantId,
        auth: sec.auth,
        localMode: sec.localMode,
        sessionId: sec.sessionId,
        ...(sec.sessionJti !== undefined ? { sessionJti: sec.sessionJti } : {}),
      });
      return {
        content: [{ type: 'text' as const, text: result.content }],
        isError: result.isError,
        ...(result.estimatedTokenCost !== undefined ? { _meta: { estimatedTokenCost: result.estimatedTokenCost } } : {}),
      };
    },
  );
}

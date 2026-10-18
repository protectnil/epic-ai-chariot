/**
 * @epicai/chariot — Generic Discovered-REST Adapter
 *
 * BUILDER task, 2026-09-30, release-blocking (team-lead: "the dogfood gate
 * requires every backend route group to be probed through the REST
 * adapter path, and discovery is a documented customer feature (README
 * "Discover Internal APIs"), so a discovered adapter that can never
 * dispatch is a product defect").
 *
 * Every hand-written REST adapter in src/engine/mcp-servers/ (paypal,
 * redshift, wikipedia, 1100+ others) is a bespoke TypeScript class with a
 * hardcoded `tools` list and a hardcoded `callTool` switch. `chariot
 * discover` produces DYNAMIC data instead — an arbitrary customer
 * codebase's {baseUrl, authType, endpoints[]} — so no per-service class can
 * exist ahead of time. This is the ONE generic class every discovered
 * service is dispatched through: it builds its `tools` list AND its
 * `callTool` routing FROM the endpoint list handed to its constructor,
 * rather than having either hardcoded.
 *
 * Wiring (src/bin/chariot.ts's discover writer): every discovered service's
 * signed payload sets `rest.module`/`rest.className` to point HERE — this
 * is what makes `ChariotState.ts`'s existing `isDispatchable()` REST branch
 * (`adapter.rest?.module && adapter.rest?.className`) recognise it with NO
 * new special-cased branch needed; `rest.envKey` carries the SAME
 * single-credential mechanism every other REST adapter already uses
 * (chariot add / chariot health / toolHandlers.ts REST dispatch all
 * resolve it identically). The one thing no existing REST adapter needed
 * before — the endpoint LIST itself, which varies per discovered service
 * and cannot be hardcoded into a class file — travels as
 * `rest.discoveredEndpointsJson` (a JSON-serialized
 * `DiscoveredEndpoint[]`) and `rest.authType`, both read out of the
 * signed payload's `rest` object by the SAME two dispatch call sites that
 * already build `apiKey`/`baseUrl` from `adapter.rest.envKey`/
 * `adapter.rest.baseUrl` (toolHandlers.ts REST dispatch;
 * setup.ts cmdQuery REST dispatch) — two additional lines at each site,
 * no new dispatch mechanism.
 *
 * Endpoint → tool mapping:
 *   - name: `<method>_<path, ":param" -> "param", non-alnum -> "_">`,
 *     deduped with a numeric suffix on collision.
 *   - Express `:paramName` path segments become REQUIRED string
 *     properties, substituted (URL-encoded) into the request path.
 *   - An OPTIONAL `query` object property is always offered (the discover
 *     scanner records method+path only — it has no query-string schema to
 *     derive real property names from; a generic key-value object is the
 *     honest representation of what IS known, not a guess at what isn't).
 *   - POST/PUT/PATCH/DELETE get an OPTIONAL `body` property, sent as the
 *     JSON request body.
 *
 * Auth (CHARIOT §10.5-style single-envKey convention — none|bearer|
 * api_key, matching src/discovery/helpers.ts's VALID_AUTH_TYPES):
 *   - 'none'      — no Authorization header.
 *   - 'bearer'    — `Authorization: Bearer <credential>`.
 *   - 'api_key'   — `X-API-Key: <credential>` (no existing convention was
 *     found anywhere in this codebase for api_key-style REST auth headers
 *     — grepped src/discovery/*.ts and every existing hand-written
 *     adapter's api-key handling; none matched a single universal header
 *     name. X-API-Key is a widely-used convention; documented here as a
 *     deliberate choice, not an assumption).
 *   - Fails CLOSED: authType !== 'none' and no credential resolved ->
 *     typed error naming the missing credential, BEFORE any network call
 *     — never a bare 401/403 the customer has to debug themselves.
 *
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

import { ToolDefinition, ToolResult } from '../engine/mcp-servers/types.js';
import { MCPAdapterBase } from '../engine/mcp-servers/base.js';

export interface DiscoveredEndpoint {
  method: string;
  path: string;
  handlerName?: string;
}

export type DiscoveredAuthType = 'none' | 'bearer' | 'api_key';

interface DiscoveredRestAdapterConfig {
  baseUrl: string;
  /** Resolved credential VALUE (already read from the env-key by the caller — matches every other REST adapter's `apiKey` convention). */
  apiKey?: string;
  authType?: string;
  /** JSON.stringify(DiscoveredEndpoint[]). */
  endpointsJson?: string;
}

interface ResolvedEndpointTool {
  method: string;
  path: string;
  handlerName?: string;
  pathParams: string[];
  hasBody: boolean;
}

function sanitizeToolNameSegment(method: string, path: string): string {
  const withParamNames = path.replace(/:([A-Za-z_][A-Za-z0-9_]*)/g, '$1');
  const base = `${method.toLowerCase()}_${withParamNames}`
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return base.length > 0 ? base : `${method.toLowerCase()}_root`;
}

/** Exported for direct unit testing of the naming/dedup rule in isolation. */
export function buildDiscoveredToolName(method: string, path: string, seen: Set<string>): string {
  const base = sanitizeToolNameSegment(method, path);
  let name = base;
  let n = 2;
  while (seen.has(name)) {
    name = `${base}_${n}`;
    n++;
  }
  seen.add(name);
  return name;
}

function extractPathParams(path: string): string[] {
  return [...path.matchAll(/:([A-Za-z_][A-Za-z0-9_]*)/g)].map((m) => m[1]);
}

const BODY_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export class DiscoveredRestAdapter extends MCPAdapterBase {
  private readonly baseUrl: string;
  private readonly apiKey: string | undefined;
  private readonly authType: DiscoveredAuthType;
  private readonly endpointsByToolName: Map<string, ResolvedEndpointTool> = new Map();
  private readonly toolDefs: ToolDefinition[] = [];

  constructor(config: DiscoveredRestAdapterConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Discovered REST adapter: configuration object is required');
    }
    if (!config.baseUrl || typeof config.baseUrl !== 'string') {
      throw new Error('Discovered REST adapter: baseUrl is required');
    }
    this.baseUrl = config.baseUrl.replace(/\/$/, '');
    this.apiKey = config.apiKey;
    const authType = config.authType;
    this.authType = authType === 'bearer' || authType === 'api_key' ? authType : 'none';

    let endpoints: DiscoveredEndpoint[] = [];
    if (config.endpointsJson) {
      try {
        const parsed: unknown = JSON.parse(config.endpointsJson);
        if (Array.isArray(parsed)) endpoints = parsed as DiscoveredEndpoint[];
      } catch {
        // A malformed endpoints payload must not crash construction — an
        // empty tool list (rather than a throw) lets `chariot health`
        // still report the adapter (0 tools, honestly) instead of the
        // whole adapter load failing closed for every OTHER adapter too.
        endpoints = [];
      }
    }

    const seen = new Set<string>();
    for (const ep of endpoints) {
      if (!ep || typeof ep.method !== 'string' || typeof ep.path !== 'string') continue;
      const method = ep.method.toUpperCase();
      const pathParams = extractPathParams(ep.path);
      const name = buildDiscoveredToolName(method, ep.path, seen);
      const hasBody = BODY_METHODS.has(method);
      this.endpointsByToolName.set(name, { method, path: ep.path, handlerName: ep.handlerName, pathParams, hasBody });

      const properties: Record<string, unknown> = {};
      for (const p of pathParams) {
        properties[p] = { type: 'string', description: `Path parameter "${p}" for ${method} ${ep.path}` };
      }
      properties['query'] = {
        type: 'object',
        description: 'Optional query-string parameters as key-value pairs. The discover scanner records method+path only, not a query schema, so this is a generic map rather than named fields.',
      };
      if (hasBody) {
        properties['body'] = { description: 'Optional JSON request body.' };
      }
      this.toolDefs.push({
        name,
        description: `${method} ${ep.path}${ep.handlerName ? ` (handler: ${ep.handlerName})` : ''} — discovered internal API endpoint.`,
        inputSchema: {
          type: 'object',
          properties,
          required: pathParams,
        },
      });
    }
  }

  get tools(): ToolDefinition[] {
    return this.toolDefs;
  }

  private authHeaders(): Record<string, string> | { error: string } {
    if (this.authType === 'none') return {};
    if (!this.apiKey) {
      return { error: `credentials_pending: this discovered adapter requires a ${this.authType} credential, but none was configured — run \`chariot add <adapter-id> --token <ENV_KEY>=<value>\` (see \`chariot health\` for the exact missing key name).` };
    }
    if (this.authType === 'bearer') return { Authorization: `Bearer ${this.apiKey}` };
    // api_key
    return { 'X-API-Key': this.apiKey };
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    const ep = this.endpointsByToolName.get(name);
    if (!ep) {
      return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
    }

    const headersOrError = this.authHeaders();
    if ('error' in headersOrError) {
      return { content: [{ type: 'text', text: headersOrError.error }], isError: true };
    }

    // Substitute path params. A required param missing from args fails
    // closed with a named error rather than sending a literal ":id"
    // segment upstream.
    let path = ep.path;
    for (const p of ep.pathParams) {
      const value = args?.[p];
      if (value === undefined || value === null || value === '') {
        return { content: [{ type: 'text', text: `Missing required path parameter "${p}" for ${ep.method} ${ep.path}` }], isError: true };
      }
      path = path.replace(`:${p}`, encodeURIComponent(String(value)));
    }

    const url = new URL(this.baseUrl + path);
    const query = args?.['query'];
    if (query && typeof query === 'object') {
      for (const [k, v] of Object.entries(query as Record<string, unknown>)) {
        if (v !== undefined && v !== null) url.searchParams.set(k, String(v));
      }
    }

    const headers: Record<string, string> = { ...headersOrError };
    let body: string | undefined;
    if (ep.hasBody && args?.['body'] !== undefined) {
      body = JSON.stringify(args['body']);
      headers['Content-Type'] = 'application/json';
    }

    try {
      const response = await this.fetchWithRetry(url.toString(), { method: ep.method, headers, body });
      const text = await response.text();
      if (!response.ok) {
        return { content: [{ type: 'text', text: `Discovered endpoint error: HTTP ${response.status} ${response.statusText}${text ? ` — ${text.slice(0, 2000)}` : ''}` }], isError: true };
      }
      return { content: [{ type: 'text', text: text.slice(0, 20000) }], isError: false };
    } catch (err) {
      return { content: [{ type: 'text', text: `Discovered endpoint request failed: ${err instanceof Error ? err.message : String(err)}` }], isError: true };
    }
  }
}

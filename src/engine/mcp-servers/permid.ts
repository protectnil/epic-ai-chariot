/**
 * PermID (Refinitiv / LSEG) MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api-eit.refinitiv.com/permid
// Auth: X-AG-Access-Token header (free, requires registration at https://permid.org/signin)
// Docs: https://permid.org/
// Category: finance
// Rate limits: Free tier 5,000 req/day

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface PermIDConfig {
  apiKey: string;
  baseUrl?: string;
}

interface PermIdHit {
  '@id'?: string;
  '@type'?: string;
  organizationName?: string;
  instrumentName?: string;
  name?: string;
  hasURL?: string;
  country?: string;
  primaryRIC?: string;
  primaryTicker?: string;
  organizationStatusCode?: string;
}

export class PermIDMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: PermIDConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('PermID: configuration object is required');
    }
    for (const __k of (['apiKey'] as Array<keyof typeof config>)) {
      if (config[__k] === undefined || config[__k] === null || (config[__k] as unknown) === '') {
        throw new Error('PermID: ' + __k + ' is required');
      }
    }
    this.apiKey = config.apiKey;
    this.baseUrl = config.baseUrl || 'https://api-eit.refinitiv.com/permid';
  }

  static catalog() {
    return {
      name: 'permid',
      displayName: 'PermID — Refinitiv / LSEG Permanent Identifier',
      version: '1.0.0',
      category: 'finance' as const,
      keywords: [
        'permid', 'refinitiv', 'lseg', 'permanent identifier', 'organization',
        'instrument', 'quote', 'ric', 'isin', 'ticker', 'lei', 'entity resolution',
        'financial data', 'company lookup', 'linked data', 'open data', 'identity',
        'securities', 'exchange listing', 'market data',
      ],
      toolNames: ['search_entities', 'get_entity'],
      description: 'PermID (Refinitiv / LSEG): search and resolve Permanent Identifiers for ~6M organizations, people, instruments, and quotes by name, ticker, RIC, ISIN, or LEI.',
      type: 'rest' as const,
      auth: {
        inferredModel: 'api-key' as const,
        probeState: 'never-probed' as const,
      },
      author: 'protectnil',
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'search_entities',
        description:
          'Search PermID for organizations, people, instruments, or quotes by name. Returns PermID, primary type, name, RIC, ticker, country, and org status. Use get_entity with the returned permid for the full linked-data record.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Free-text search term (company name, ticker, person name, etc.)',
            },
            entity_type: {
              type: 'string',
              description: 'Restrict results by entity type',
              enum: ['organization', 'person', 'instrument', 'quote', 'all'],
            },
            limit: {
              type: 'number',
              description: 'Maximum results per entity bucket, 1–100 (default 20)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_entity',
        description:
          'Fetch the full PermID linked-data record by ID. For organizations: legal name, headquarters, identifiers (RIC, ISIN, ticker, LEI), industry codes, public/private status. For people: name, type, affiliations.',
        inputSchema: {
          type: 'object',
          properties: {
            permid: {
              type: 'string',
              description: 'PermID numeric string (e.g. "4295905573")',
            },
          },
          required: ['permid'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_entities': return this.searchEntities(args);
        case 'get_entity':      return this.getEntity(args);
        default:
          return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
      }
    } catch (error) {
      return {
        content: [{ type: 'text', text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}` }],
        isError: true,
      };
    }
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private authHeaders(): Record<string, string> {
    return {
      'X-AG-Access-Token': this.apiKey,
      'Accept': 'application/json',
    };
  }

  private async permidRequest(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: this.authHeaders(),
    });
    if (response.status === 401 || response.status === 403) {
      return {
        content: [{ type: 'text', text: `PermID: unauthorized (HTTP ${response.status}). Check the API key registered at https://permid.org/signin` }],
        isError: true,
      };
    }
    if (response.status === 429) {
      return {
        content: [{ type: 'text', text: 'PermID: rate-limit hit (HTTP 429). Free tier allows 5,000 requests/day.' }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `PermID API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async searchEntities(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    const entityType = (args.entity_type as string | undefined) ?? 'all';
    const limit = Math.min(100, Math.max(1, (args.limit as number | undefined) ?? 20));

    const params = new URLSearchParams({
      q: query,
      format: 'json',
      numOfMatchesPerEntityType: String(limit),
    });
    if (entityType && entityType !== 'all') {
      params.set('entityType', entityType);
    }

    const url = `${this.baseUrl}/search?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: this.authHeaders(),
    });

    if (response.status === 401 || response.status === 403) {
      return {
        content: [{ type: 'text', text: `PermID: unauthorized (HTTP ${response.status}). Check the API key registered at https://permid.org/signin` }],
        isError: true,
      };
    }
    if (response.status === 429) {
      return {
        content: [{ type: 'text', text: 'PermID: rate-limit hit (HTTP 429). Free tier allows 5,000 requests/day.' }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `PermID API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }

    const data = await response.json() as {
      result?: {
        organizations?: { entities?: PermIdHit[] };
        instruments?: { entities?: PermIdHit[] };
        quotes?: { entities?: PermIdHit[] };
        people?: { entities?: PermIdHit[] };
      };
    };

    const buckets = data.result ?? {};
    const normalized = {
      organizations: (buckets.organizations?.entities ?? []).map(this.normalizeHit),
      instruments:   (buckets.instruments?.entities ?? []).map(this.normalizeHit),
      quotes:        (buckets.quotes?.entities ?? []).map(this.normalizeHit),
      people:        (buckets.people?.entities ?? []).map(this.normalizeHit),
    };

    return { content: [{ type: 'text', text: this.truncate(normalized) }], isError: false };
  }

  private normalizeHit(h: PermIdHit): Record<string, string | null> {
    return {
      permid_url:      h['@id'] ?? null,
      permid:          h['@id']?.replace(/^https?:\/\/permid\.org\/(\d+).*$/, '$1') ?? null,
      type:            h['@type'] ?? null,
      name:            h.organizationName ?? h.instrumentName ?? h.name ?? null,
      primary_ric:     h.primaryRIC ?? null,
      primary_ticker:  h.primaryTicker ?? null,
      country:         h.country ?? null,
      org_status:      h.organizationStatusCode ?? null,
      homepage:        h.hasURL ?? null,
    };
  }

  private async getEntity(args: Record<string, unknown>): Promise<ToolResult> {
    const permid = args.permid as string;
    // PermID record endpoint returns JSON-LD
    return this.permidRequest(`/1-${encodeURIComponent(permid)}?format=json-ld`);
  }
}

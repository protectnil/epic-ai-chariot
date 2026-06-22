/**
 * GovInfo.gov MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: https://api.govinfo.gov (GPO's public GovInfo REST API)
// Auth: api_key query parameter — free key from https://api.data.gov/signup
// Docs: https://api.govinfo.gov/docs
// Collections: BILLS, USCODE, CFR, eCFR, FR, CREC, CHRG, CRPT, HMAN, PLAW, SERIALSET, USCOURTS
// Rate limits: 1,000 requests/hour (default data.gov key tier)

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface GovInfoConfig {
  apiKey: string;
  baseUrl?: string;
}

export class GovInfoMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config: GovInfoConfig) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('GovInfo: configuration object is required');
    }
    if (!config.apiKey || typeof config.apiKey !== 'string' || !config.apiKey.trim()) {
      throw new Error('GovInfo: apiKey is required — register at https://api.data.gov/signup');
    }
    this.apiKey = config.apiKey.trim();
    this.baseUrl = config.baseUrl ?? 'https://api.govinfo.gov';
  }

  static catalog() {
    return {
      name: 'govinfo',
      displayName: 'GovInfo.gov',
      version: '1.0.0',
      category: 'government',
      keywords: [
        'govinfo', 'government', 'congress', 'legislation', 'federal register',
        'CFR', 'code of federal regulations', 'US code', 'bills', 'statutes',
        'public laws', 'congressional record', 'GPO', 'federal documents',
        'regulations', 'hearings', 'reports', 'US courts', 'PLAW', 'USCODE',
      ],
      toolNames: ['list_collections', 'search_packages', 'get_package', 'list_granules', 'get_granule'],
      description: 'GovInfo.gov: search and retrieve authoritative full-text US government publications — bills, laws, CFR, Federal Register, congressional records, hearings, and more.',
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
        name: 'list_collections',
        description:
          'List all GovInfo collections (BILLS, CFR, USCODE, FR, CHRG, CRPT, HMAN, PLAW, SERIALSET, USCOURTS, etc.) with package and granule counts. Use the collection code with search_packages to filter results.',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'search_packages',
        description:
          'Full-text and faceted search across GovInfo. Filter by collection codes (comma-separated), date range, congress number, and free-text query. Returns package IDs and titles.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Free-text search query',
            },
            collections: {
              type: 'string',
              description: 'Comma-separated collection codes, e.g. "BILLS,FR" or "CFR"',
            },
            congress: {
              type: 'number',
              description: 'Congress number (e.g., 118) — filters BILLS, CHRG, CRPT collections',
            },
            date_from: {
              type: 'string',
              description: 'Start of date range in YYYY-MM-DD format',
            },
            date_to: {
              type: 'string',
              description: 'End of date range in YYYY-MM-DD format',
            },
            page_size: {
              type: 'number',
              description: 'Number of results per page, 1–100 (default 25)',
            },
            offset_mark: {
              type: 'string',
              description: 'Pagination cursor returned in a prior response (default "*" for first page)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_package',
        description:
          'Get metadata for a single GovInfo package by packageId (e.g., "BILLS-118hr1234ih", "FR-2024-05-12", "PLAW-117publ328"). Returns title, dates, citations, granule count, and download links.',
        inputSchema: {
          type: 'object',
          properties: {
            package_id: {
              type: 'string',
              description: 'GovInfo packageId, e.g. "BILLS-118hr1234ih" or "FR-2024-05-12"',
            },
          },
          required: ['package_id'],
        },
      },
      {
        name: 'list_granules',
        description:
          'List granules (sub-units) within a package — e.g., individual sections of a CFR title or entries in a Federal Register issue. Returns granule IDs and titles.',
        inputSchema: {
          type: 'object',
          properties: {
            package_id: {
              type: 'string',
              description: 'GovInfo packageId',
            },
            page_size: {
              type: 'number',
              description: 'Number of granules per page, 1–100 (default 100)',
            },
            offset_mark: {
              type: 'string',
              description: 'Pagination cursor from a prior response',
            },
          },
          required: ['package_id'],
        },
      },
      {
        name: 'get_granule',
        description: 'Get metadata for a single granule (sub-unit) within a GovInfo package.',
        inputSchema: {
          type: 'object',
          properties: {
            package_id: {
              type: 'string',
              description: 'GovInfo packageId',
            },
            granule_id: {
              type: 'string',
              description: 'Granule ID within the package',
            },
          },
          required: ['package_id', 'granule_id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'list_collections':  return this.listCollections();
        case 'search_packages':   return this.searchPackages(args);
        case 'get_package':       return this.getPackage(args);
        case 'list_granules':     return this.listGranules(args);
        case 'get_granule':       return this.getGranule(args);
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

  /** GET with api_key appended as query param */
  private async get(path: string, params: Record<string, string> = {}): Promise<ToolResult> {
    const qs = new URLSearchParams({ ...params, api_key: this.apiKey });
    const url = `${this.baseUrl}${path}?${qs}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `GovInfo API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  /** POST with api_key as query param, JSON body */
  private async post(path: string, body: unknown): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}?api_key=${encodeURIComponent(this.apiKey)}`;
    const response = await this.fetchWithRetry(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `GovInfo API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async listCollections(): Promise<ToolResult> {
    return this.get('/collections');
  }

  private async searchPackages(args: Record<string, unknown>): Promise<ToolResult> {
    const filters: string[] = [`query:"${String(args.query).replace(/"/g, '\\"')}"`];
    if (args.collections) filters.push(`collection:(${String(args.collections)})`);
    if (args.congress) filters.push(`congress:${Number(args.congress)}`);
    if (args.date_from && args.date_to) {
      filters.push(`publishdate:range(${args.date_from},${args.date_to})`);
    } else if (args.date_from) {
      filters.push(`publishdate:range(${args.date_from},)`);
    } else if (args.date_to) {
      filters.push(`publishdate:range(,${args.date_to})`);
    }

    const pageSize = Math.min(100, Math.max(1, typeof args.page_size === 'number' ? args.page_size : 25));
    const offsetMark = typeof args.offset_mark === 'string' ? args.offset_mark : '*';

    const body = {
      query: filters.join(' AND '),
      pageSize,
      offsetMark,
      sorts: [{ field: 'relevancy', sortOrder: 'DESC' }],
    };

    return this.post('/search', body);
  }

  private async getPackage(args: Record<string, unknown>): Promise<ToolResult> {
    const packageId = this.requireString(args, 'package_id', '"BILLS-118hr1234ih"');
    return this.get(`/packages/${encodeURIComponent(packageId)}/summary`);
  }

  private async listGranules(args: Record<string, unknown>): Promise<ToolResult> {
    const packageId = this.requireString(args, 'package_id', '"FR-2024-05-12"');
    const pageSize = Math.min(100, Math.max(1, typeof args.page_size === 'number' ? args.page_size : 100));
    const offsetMark = typeof args.offset_mark === 'string' ? args.offset_mark : '*';
    return this.get(`/packages/${encodeURIComponent(packageId)}/granules`, {
      pageSize: String(pageSize),
      offsetMark,
    });
  }

  private async getGranule(args: Record<string, unknown>): Promise<ToolResult> {
    const packageId = this.requireString(args, 'package_id', '"PLAW-117publ328"');
    const granuleId = this.requireString(args, 'granule_id', '"<granule_id>"');
    return this.get(
      `/packages/${encodeURIComponent(packageId)}/granules/${encodeURIComponent(granuleId)}/summary`,
    );
  }

  private requireString(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`GovInfo: required argument "${key}" is missing or empty. Pass a string like ${example}.`);
    }
    return v.trim();
  }
}

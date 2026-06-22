/**
 * Catalogue of Life MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.checklistbank.org
// Auth: None required — ChecklistBank / Catalogue of Life API is public and free.
// Docs: https://api.checklistbank.org/openapi/
// Default dataset key: 3LR = COL latest release
// Rate limits: Fair-use; no published hard limit.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface CatalogueOfLifeConfig {
  /** Optional base URL override (default: https://api.checklistbank.org) */
  baseUrl?: string;
}

const DEFAULT_DATASET = '3LR';

export class CatalogueOfLifeMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config: CatalogueOfLifeConfig = {}) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Catalogue of Life: configuration object is required');
    }
    this.baseUrl = config.baseUrl ?? 'https://api.checklistbank.org';
  }

  static catalog() {
    return {
      name: 'catalogueoflife',
      displayName: 'Catalogue of Life',
      version: '1.0.0',
      category: 'science',
      keywords: [
        'catalogue of life', 'col', 'checklistbank', 'taxonomy', 'taxon',
        'species', 'scientific name', 'vernacular name', 'classification',
        'kingdom', 'phylum', 'genus', 'family', 'biodiversity', 'nomenclature',
        'synonyms', 'name usage', 'biological names', 'flora', 'fauna',
      ],
      toolNames: [
        'search',
        'name_match',
        'usage',
        'taxon',
        'classification',
        'vernacular',
        'synonyms',
        'children',
      ],
      description: 'Catalogue of Life (ChecklistBank) API: name-usage search, exact scientific-name matching, single usage/taxon lookup, taxonomic classification chains, vernacular names, synonyms, and direct child taxa — all from the global taxonomic index, free and unauthenticated.',
      type: 'rest' as const,
      auth: {
        inferredModel: 'none' as const,
        probeState: 'no-auth-verified' as const,
      },
      author: 'protectnil',
    };
  }

  get tools(): ToolDefinition[] {
    return [
      {
        name: 'search',
        description: 'Name-usage search across a ChecklistBank dataset (default: COL latest release). Returns matching taxa with rank, status, and classification context.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Free-text search term (e.g. "Panthera leo").',
            },
            dataset: {
              type: 'string',
              description: `ChecklistBank dataset key (default "${DEFAULT_DATASET}" = COL latest release).`,
            },
            limit: {
              type: 'number',
              description: 'Number of results to return, 1–1000 (default 25).',
            },
            offset: {
              type: 'number',
              description: 'Zero-based result offset for pagination (default 0).',
            },
            rank: {
              type: 'string',
              description: 'Filter by taxonomic rank, e.g. "species", "genus", "family".',
            },
            status: {
              type: 'string',
              description: 'Filter by name status: accepted | synonym | bare_name | misapplied | …',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'name_match',
        description: 'Exact scientific-name match returning 0 or 1 primary hit plus ranked alternatives. Use authorship to disambiguate homonyms.',
        inputSchema: {
          type: 'object',
          properties: {
            scientific_name: {
              type: 'string',
              description: 'Scientific name to match (e.g. "Panthera leo").',
            },
            authorship: {
              type: 'string',
              description: 'Optional authorship string to disambiguate homonyms (e.g. "(Linnaeus, 1758)").',
            },
            dataset: {
              type: 'string',
              description: `ChecklistBank dataset key (default "${DEFAULT_DATASET}" = COL latest release).`,
            },
          },
          required: ['scientific_name'],
        },
      },
      {
        name: 'usage',
        description: 'Retrieve a single name-usage record by its ChecklistBank usage ID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'ChecklistBank name-usage ID.',
            },
            dataset: {
              type: 'string',
              description: `ChecklistBank dataset key (default "${DEFAULT_DATASET}" = COL latest release).`,
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'taxon',
        description: 'Retrieve a single taxon record by its ChecklistBank taxon ID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'ChecklistBank taxon ID.',
            },
            dataset: {
              type: 'string',
              description: `ChecklistBank dataset key (default "${DEFAULT_DATASET}" = COL latest release).`,
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'classification',
        description: 'Return the full taxonomic classification chain (kingdom → species) for a taxon ID.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'ChecklistBank taxon ID.',
            },
            dataset: {
              type: 'string',
              description: `ChecklistBank dataset key (default "${DEFAULT_DATASET}" = COL latest release).`,
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'vernacular',
        description: 'Return vernacular (common) names for a taxon.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'ChecklistBank taxon ID.',
            },
            dataset: {
              type: 'string',
              description: `ChecklistBank dataset key (default "${DEFAULT_DATASET}" = COL latest release).`,
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'synonyms',
        description: 'Return synonyms of a taxon.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'ChecklistBank taxon ID.',
            },
            dataset: {
              type: 'string',
              description: `ChecklistBank dataset key (default "${DEFAULT_DATASET}" = COL latest release).`,
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'children',
        description: 'Return direct child taxa of a taxon.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'ChecklistBank taxon ID.',
            },
            dataset: {
              type: 'string',
              description: `ChecklistBank dataset key (default "${DEFAULT_DATASET}" = COL latest release).`,
            },
            limit: {
              type: 'number',
              description: 'Number of child taxa to return, 1–1000 (default 100).',
            },
          },
          required: ['id'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search':         return this.search(args);
        case 'name_match':     return this.nameMatch(args);
        case 'usage':          return this.getUsage(args);
        case 'taxon':          return this.getTaxon(args);
        case 'classification': return this.getClassification(args);
        case 'vernacular':     return this.getVernacular(args);
        case 'synonyms':       return this.getSynonyms(args);
        case 'children':       return this.getChildren(args);
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

  private datasetKey(args: Record<string, unknown>): string {
    const v = args.dataset;
    if (typeof v === 'string' && v.trim()) return v.trim();
    return DEFAULT_DATASET;
  }

  private reqStr(args: Record<string, unknown>, key: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing or empty.`);
    }
    return v;
  }

  private async request(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async search(args: Record<string, unknown>): Promise<ToolResult> {
    const ds = this.datasetKey(args);
    const params = new URLSearchParams({
      q: this.reqStr(args, 'query'),
      limit: String(Math.min(1000, Math.max(1, Number(args.limit ?? 25)))),
      offset: String(Math.max(0, Number(args.offset ?? 0))),
    });
    if (args.rank) params.set('rank', String(args.rank));
    if (args.status) params.set('status', String(args.status));
    return this.request(`/dataset/${encodeURIComponent(ds)}/nameusage/search?${params.toString()}`);
  }

  private async nameMatch(args: Record<string, unknown>): Promise<ToolResult> {
    const ds = this.datasetKey(args);
    const params = new URLSearchParams({ q: this.reqStr(args, 'scientific_name') });
    if (args.authorship) params.set('authorship', String(args.authorship));
    return this.request(`/dataset/${encodeURIComponent(ds)}/match/nameusage?${params.toString()}`);
  }

  private async getUsage(args: Record<string, unknown>): Promise<ToolResult> {
    const ds = this.datasetKey(args);
    const id = encodeURIComponent(this.reqStr(args, 'id'));
    return this.request(`/dataset/${encodeURIComponent(ds)}/nameusage/${id}`);
  }

  private async getTaxon(args: Record<string, unknown>): Promise<ToolResult> {
    const ds = this.datasetKey(args);
    const id = encodeURIComponent(this.reqStr(args, 'id'));
    return this.request(`/dataset/${encodeURIComponent(ds)}/taxon/${id}`);
  }

  private async getClassification(args: Record<string, unknown>): Promise<ToolResult> {
    const ds = this.datasetKey(args);
    const id = encodeURIComponent(this.reqStr(args, 'id'));
    return this.request(`/dataset/${encodeURIComponent(ds)}/taxon/${id}/classification`);
  }

  private async getVernacular(args: Record<string, unknown>): Promise<ToolResult> {
    const ds = this.datasetKey(args);
    const id = encodeURIComponent(this.reqStr(args, 'id'));
    return this.request(`/dataset/${encodeURIComponent(ds)}/taxon/${id}/vernacular`);
  }

  private async getSynonyms(args: Record<string, unknown>): Promise<ToolResult> {
    const ds = this.datasetKey(args);
    const id = encodeURIComponent(this.reqStr(args, 'id'));
    return this.request(`/dataset/${encodeURIComponent(ds)}/taxon/${id}/synonyms`);
  }

  private async getChildren(args: Record<string, unknown>): Promise<ToolResult> {
    const ds = this.datasetKey(args);
    const id = encodeURIComponent(this.reqStr(args, 'id'));
    const limit = Math.min(1000, Math.max(1, Number(args.limit ?? 100)));
    return this.request(`/dataset/${encodeURIComponent(ds)}/taxon/${id}/children?limit=${limit}`);
  }
}

/**
 * GBIF (Global Biodiversity Information Facility) MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

//
// Base URL: https://api.gbif.org/v1
// Auth: None required — GBIF API v1 is public and free with no auth.
// Docs: https://www.gbif.org/developer/summary
// Rate limits: Fair-use; no published hard limit. Keep requests reasonable.

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface GBIFConfig {
  /** Optional base URL override (default: https://api.gbif.org/v1) */
  baseUrl?: string;
}

export class GBIFMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config: GBIFConfig = {}) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('GBIF: configuration object is required');
    }
    this.baseUrl = config.baseUrl ?? 'https://api.gbif.org/v1';
  }

  static catalog() {
    return {
      name: 'gbif',
      displayName: 'GBIF — Global Biodiversity Information Facility',
      version: '1.0.0',
      category: 'science',
      keywords: [
        'gbif', 'biodiversity', 'species', 'taxonomy', 'occurrence',
        'natural history', 'biology', 'fauna', 'flora', 'taxon',
        'scientific name', 'specimen', 'georeferenced', 'ecology',
        'classification', 'kingdom', 'phylum', 'genus', 'family',
      ],
      toolNames: ['search_species', 'get_species', 'get_occurrences'],
      description: 'GBIF API v1: full-text species backbone search, single-taxon lookup by key, and georeferenced occurrence retrieval — all from the Global Biodiversity Information Facility, free and unauthenticated.',
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
        name: 'search_species',
        description: 'Search GBIF species backbone by name or keyword. Returns matched taxa with rank, status, and classification.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Species name or keyword (e.g., "Homo sapiens", "oak")',
            },
            limit: {
              type: 'number',
              description: 'Maximum results to return (1-100, default 20)',
            },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_species',
        description: 'Get full taxonomic details for a GBIF species by its integer taxon key. Use search_species first to find the key.',
        inputSchema: {
          type: 'object',
          properties: {
            key: {
              type: 'number',
              description: 'GBIF taxon key (integer)',
            },
          },
          required: ['key'],
        },
      },
      {
        name: 'get_occurrences',
        description: 'Retrieve georeferenced occurrence records for a taxon. Optionally filter by ISO 3166-1 alpha-2 country code.',
        inputSchema: {
          type: 'object',
          properties: {
            key: {
              type: 'number',
              description: 'GBIF taxon key (integer)',
            },
            limit: {
              type: 'number',
              description: 'Maximum records to return (1-300, default 20)',
            },
            country: {
              type: 'string',
              description: 'ISO 3166-1 alpha-2 country code to filter occurrences (e.g., "US", "DE")',
            },
          },
          required: ['key'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_species': return this.searchSpecies(args);
        case 'get_species':    return this.getSpecies(args);
        case 'get_occurrences': return this.getOccurrences(args);
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

  private async request(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private async searchSpecies(args: Record<string, unknown>): Promise<ToolResult> {
    const query = args.query as string;
    const limit = Math.min(100, Math.max(1, Number(args.limit ?? 20)));
    const params = new URLSearchParams({ q: query, limit: String(limit) });
    return this.request(`/species/search?${params.toString()}`);
  }

  private async getSpecies(args: Record<string, unknown>): Promise<ToolResult> {
    const key = args.key as number;
    return this.request(`/species/${encodeURIComponent(String(key))}`);
  }

  private async getOccurrences(args: Record<string, unknown>): Promise<ToolResult> {
    const key = args.key as number;
    const limit = Math.min(300, Math.max(1, Number(args.limit ?? 20)));
    const params = new URLSearchParams({
      taxonKey: String(key),
      limit: String(limit),
    });
    if (args.country) {
      params.set('country', args.country as string);
    }
    return this.request(`/occurrence/search?${params.toString()}`);
  }
}

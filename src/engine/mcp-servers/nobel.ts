/**
 * Nobel Prize API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Upstream: Nobel Prize API v2 (free, no auth)
// Base URL: https://api.nobelprize.org/2.1
// Docs: https://app.swaggerhub.com/apis/NobelMedia/NobelMasterData/2.1
// Category: education
// Rate limits: None documented — public, unauthenticated

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

export class NobelMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('NobelMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? 'https://api.nobelprize.org/2.1';
  }

  static catalog() {
    return {
      name: 'nobel',
      displayName: 'Nobel Prize API',
      version: '1.0.0',
      category: 'education',
      keywords: [
        'nobel', 'nobel prize', 'laureate', 'physics', 'chemistry',
        'medicine', 'literature', 'peace', 'economics', 'prize',
        'award', 'history', 'science',
      ],
      toolNames: ['search_laureates', 'get_prizes_by_year'],
      description: 'Nobel Prize API: search Nobel laureates by name or category and retrieve all prizes awarded in a given year.',
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
        name: 'search_laureates',
        description:
          'Search Nobel Prize laureates by name and/or prize category. Returns biography, prizes won, and motivation.',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'Full or partial name of the laureate (e.g., "Einstein", "Marie Curie")',
            },
            category: {
              type: 'string',
              description:
                'Nobel Prize category: phy (Physics), che (Chemistry), med (Medicine), lit (Literature), pea (Peace), eco (Economics)',
            },
          },
        },
      },
      {
        name: 'get_prizes_by_year',
        description:
          'Get all Nobel Prizes awarded in a specific year, optionally filtered by category.',
        inputSchema: {
          type: 'object',
          properties: {
            year: {
              type: 'number',
              description: 'Year to look up (e.g., 2023). Must be 1901 or later.',
            },
            category: {
              type: 'string',
              description:
                'Nobel Prize category: phy (Physics), che (Chemistry), med (Medicine), lit (Literature), pea (Peace), eco (Economics)',
            },
          },
          required: ['year'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_laureates':
          return this.searchLaureates(args);
        case 'get_prizes_by_year':
          return this.getPrizesByYear(args);
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

  private async searchLaureates(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({ limit: '20', format: 'json' });
    if (typeof args.name === 'string' && args.name) {
      params.set('name', args.name);
    }
    if (typeof args.category === 'string' && args.category) {
      params.set('nobelPrizeCategory', args.category);
    }

    const url = `${this.baseUrl}/laureates?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Nobel API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as {
      laureates?: {
        id: string;
        knownName?: { en?: string };
        fullName?: { en?: string };
        born?: string;
        died?: string;
        bornCountry?: { en?: string };
        gender?: string;
        nobelPrizes?: {
          awardYear: string;
          category?: { en?: string };
          categoryFullName?: { en?: string };
          motivation?: { en?: string };
          prizeStatus?: string;
        }[];
        wikipedia?: { english?: string };
      }[];
      meta?: { count: number };
    };

    if (!data.laureates || data.laureates.length === 0) {
      return { content: [{ type: 'text', text: this.truncate({ count: 0, laureates: [] }) }], isError: false };
    }

    const result = {
      count: data.meta?.count ?? data.laureates.length,
      laureates: data.laureates.map((l) => ({
        id: l.id,
        name: l.knownName?.en ?? l.fullName?.en ?? null,
        full_name: l.fullName?.en ?? null,
        born: l.born ?? null,
        died: l.died ?? null,
        birth_country: l.bornCountry?.en ?? null,
        gender: l.gender ?? null,
        wikipedia: l.wikipedia?.english ?? null,
        prizes: (l.nobelPrizes ?? []).map((p) => ({
          year: p.awardYear,
          category: p.category?.en ?? null,
          category_full: p.categoryFullName?.en ?? null,
          motivation: p.motivation?.en ?? null,
          status: p.prizeStatus ?? null,
        })),
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getPrizesByYear(args: Record<string, unknown>): Promise<ToolResult> {
    const year = args.year as number;
    const params = new URLSearchParams({
      nobelPrizeYear: String(year),
      format: 'json',
      limit: '20',
    });
    if (typeof args.category === 'string' && args.category) {
      params.set('nobelPrizeCategory', args.category);
    }

    const url = `${this.baseUrl}/nobelPrizes?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Nobel API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as {
      nobelPrizes?: {
        awardYear: string;
        category?: { en?: string };
        categoryFullName?: { en?: string };
        dateAwarded?: string;
        prizeMotivation?: { en?: string };
        prizeAmount?: number;
        laureates?: {
          id?: string;
          knownName?: { en?: string };
          fullName?: { en?: string };
          motivation?: { en?: string };
          portion?: string;
        }[];
      }[];
      meta?: { count: number };
    };

    if (!data.nobelPrizes || data.nobelPrizes.length === 0) {
      return { content: [{ type: 'text', text: this.truncate({ year, count: 0, prizes: [] }) }], isError: false };
    }

    const result = {
      year,
      count: data.nobelPrizes.length,
      prizes: data.nobelPrizes.map((p) => ({
        category: p.category?.en ?? null,
        category_full: p.categoryFullName?.en ?? null,
        date_awarded: p.dateAwarded ?? null,
        motivation: p.prizeMotivation?.en ?? null,
        prize_amount_sek: p.prizeAmount ?? null,
        laureates: (p.laureates ?? []).map((l) => ({
          id: l.id ?? null,
          name: l.knownName?.en ?? l.fullName?.en ?? null,
          motivation: l.motivation?.en ?? null,
          portion: l.portion ?? null,
        })),
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}

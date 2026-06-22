/**
 * FBI Wanted MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.fbi.gov/@wanted
// Auth: None — public, unauthenticated API
// Docs: https://api.fbi.gov/
// Category: government
// Rate limits: None published — reasonable use expected

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.fbi.gov/@wanted';

export class FbiWantedMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('FbiWantedMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'fbiwanted',
      displayName: 'FBI Wanted',
      version: '1.0.0',
      category: 'government',
      keywords: [
        'fbi', 'wanted', 'fugitive', 'most wanted', 'law enforcement',
        'criminal', 'suspect', 'federal', 'bureau', 'investigation',
        'fugitives', 'missing', 'reward',
      ],
      toolNames: ['search_wanted', 'get_wanted_person'],
      description: 'FBI Wanted API: search the FBI Most Wanted list and retrieve full details for individual wanted persons — free, public, no authentication required.',
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
        name: 'search_wanted',
        description:
          'Search the FBI Most Wanted list. Optionally filter by a keyword (name, crime type, etc.) and paginate through results.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description:
                'Search keyword (e.g., a name, crime type, or description). Omit to list all wanted persons.',
            },
            page: {
              type: 'number',
              description: 'Page number for pagination (default 1)',
            },
          },
        },
      },
      {
        name: 'get_wanted_person',
        description: 'Get full details for a specific FBI Wanted person by their UID.',
        inputSchema: {
          type: 'object',
          properties: {
            uid: {
              type: 'string',
              description: 'The unique identifier (UID) of the wanted person',
            },
          },
          required: ['uid'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_wanted':
          return this.searchWanted(args.query as string | undefined, args.page as number | undefined);
        case 'get_wanted_person':
          return this.getWantedPerson(args.uid as string);
        default:
          return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
      }
    } catch (error) {
      return {
        content: [
          {
            type: 'text',
            text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  }

  // ── Private helpers ──────────────────────────────────────────────────────────

  private async searchWanted(query?: string, page = 1): Promise<ToolResult> {
    const params = new URLSearchParams({ page: String(page) });
    if (query) params.set('title', query);

    const url = `${this.baseUrl}?${params}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `FBI API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as {
      total: number;
      page: number;
      items: Array<{
        uid: string;
        title: string;
        subjects: string[] | null;
        description: string | null;
        url: string | null;
        images: Array<{ original: string; thumb: string; caption: string | null }> | null;
      }>;
    };

    const result = {
      query: query ?? null,
      page: data.page,
      total: data.total,
      items: (data.items ?? []).map((p) => ({
        uid: p.uid,
        title: p.title,
        subjects: p.subjects ?? [],
        description: p.description ?? null,
        images: (p.images ?? []).map((img) => ({
          original: img.original,
          thumb: img.thumb,
          caption: img.caption ?? null,
        })),
        url: p.url ?? null,
      })),
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getWantedPerson(uid: string): Promise<ToolResult> {
    const url = `${this.baseUrl}/${encodeURIComponent(uid)}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `FBI API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const p = (await response.json()) as {
      uid: string;
      title: string;
      subjects: string[] | null;
      description: string | null;
      details: string | null;
      caution: string | null;
      status: string | null;
      reward_text: string | null;
      aliases: string[] | null;
      nationality: string | null;
      place_of_birth: string | null;
      dates_of_birth_used: string[] | null;
      sex: string | null;
      race: string | null;
      eyes: string | null;
      hair: string | null;
      height_min: number | null;
      height_max: number | null;
      weight_min: number | null;
      weight_max: number | null;
      scars_and_marks: string | null;
      occupations: string[] | null;
      languages: string[] | null;
      field_offices: string[] | null;
      locations: string[] | null;
      images: Array<{ original: string; thumb: string; caption: string | null }> | null;
      files: Array<{ name: string; url: string }> | null;
      url: string | null;
      publication: string | null;
      modified: string | null;
    };

    const result = {
      uid: p.uid,
      title: p.title,
      subjects: p.subjects ?? [],
      description: p.description ?? null,
      details: p.details ?? null,
      caution: p.caution ?? null,
      status: p.status ?? null,
      reward_text: p.reward_text ?? null,
      aliases: p.aliases ?? [],
      nationality: p.nationality ?? null,
      place_of_birth: p.place_of_birth ?? null,
      dates_of_birth_used: p.dates_of_birth_used ?? [],
      physical: {
        sex: p.sex ?? null,
        race: p.race ?? null,
        eyes: p.eyes ?? null,
        hair: p.hair ?? null,
        height_min: p.height_min ?? null,
        height_max: p.height_max ?? null,
        weight_min: p.weight_min ?? null,
        weight_max: p.weight_max ?? null,
        scars_and_marks: p.scars_and_marks ?? null,
      },
      occupations: p.occupations ?? [],
      languages: p.languages ?? [],
      field_offices: p.field_offices ?? [],
      locations: p.locations ?? [],
      images: (p.images ?? []).map((img) => ({
        original: img.original,
        thumb: img.thumb,
        caption: img.caption ?? null,
      })),
      files: (p.files ?? []).map((f) => ({ name: f.name, url: f.url })),
      url: p.url ?? null,
      publication: p.publication ?? null,
      modified: p.modified ?? null,
    };

    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}

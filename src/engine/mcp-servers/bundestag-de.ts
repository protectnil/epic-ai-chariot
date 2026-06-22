/**
 * Bundestag DIP REST Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Upstream: Dokumentations- und Informationssystem für Parlamentarische Vorgänge (DIP)
 * Base URL: https://search.dip.bundestag.de/api/v1
 * Auth: ?apikey= query parameter — optional; a public demo key is provided by
 *       the Bundestag on https://dip.bundestag.de/über-dip/hilfe/api.
 *       Operators should register their own key at the same URL.
 * Docs: https://dip.bundestag.de/über-dip/hilfe/api
 * Category: government
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

// Bundestag-published demo key (freely available on the official DIP help page).
const PUBLIC_DEMO_KEY = 'rgsaY4U.oZRQKUHdJhF9qguHMkwCGIoLaSc3Bdgwod';

interface BundestagDipConfig {
  apiKey?: string;
  baseUrl?: string;
}

export class BundestagDeMCPServer extends MCPAdapterBase {
  private readonly apiKey: string;
  private readonly baseUrl: string;

  constructor(config?: BundestagDipConfig) {
    super();
    if (config === null) { throw new Error('BundestagDeMCPServer: configuration object is required when provided'); }
    this.apiKey = config?.apiKey?.trim() || PUBLIC_DEMO_KEY;
    this.baseUrl = config?.baseUrl || 'https://search.dip.bundestag.de/api/v1';
  }

  static catalog() {
    return {
      name: 'bundestag-de',
      displayName: 'Bundestag DIP — German Parliamentary Information System',
      version: '1.0.0',
      category: 'government',
      keywords: [
        'bundestag', 'bundesrat', 'germany', 'parliament', 'legislation',
        'drucksachen', 'plenarprotokoll', 'plenary', 'bills', 'motions',
        'parliamentary', 'DIP', 'German law', 'Gesetzentwurf', 'Anfrage',
        'Beschlussempfehlung', 'MdB', 'member of parliament', 'activity feed',
      ],
      toolNames: [
        'search_activities',
        'search_drucksachen',
        'get_drucksache',
        'search_plenarprotokolle',
        'get_plenarprotokoll',
        'search_persons',
      ],
      description: 'Bundestag DIP API: search and retrieve German parliamentary documents (Drucksachen), plenary transcripts (Plenarprotokolle), combined activity feeds, and people referenced in parliamentary proceedings.',
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
        name: 'search_activities',
        description: 'Combined activity feed across Bundestag and Bundesrat. Returns the latest parliamentary activities matching the given filters.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Free-text search term — German recommended (e.g. "Klimaschutz")',
            },
            ressort: {
              type: 'string',
              description: 'Filter by Ministerium abbreviation (e.g. "BMI", "BMF")',
            },
            descriptor: {
              type: 'string',
              description: 'GND subject descriptor (e.g. "Klimaschutz", "Gesundheitspolitik")',
            },
            date_from: {
              type: 'string',
              description: 'Start date filter in YYYY-MM-DD format',
            },
            date_to: {
              type: 'string',
              description: 'End date filter in YYYY-MM-DD format',
            },
            cursor: {
              type: 'string',
              description: 'Pagination cursor returned from a prior page response',
            },
            num: {
              type: 'number',
              description: 'Number of results to return (1–200, default 50)',
            },
          },
        },
      },
      {
        name: 'search_drucksachen',
        description: 'Search printed documents (Drucksachen): bills, motions, small inquiries, committee recommendations, and answers.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Free-text search term',
            },
            drucksachentyp: {
              type: 'string',
              description: 'Document type filter (e.g. "Antrag", "Gesetzentwurf", "Beschlussempfehlung", "Kleine Anfrage")',
            },
            date_from: {
              type: 'string',
              description: 'Start date filter in YYYY-MM-DD format',
            },
            date_to: {
              type: 'string',
              description: 'End date filter in YYYY-MM-DD format',
            },
            cursor: {
              type: 'string',
              description: 'Pagination cursor returned from a prior page response',
            },
            num: {
              type: 'number',
              description: 'Number of results to return (1–200, default 50)',
            },
          },
        },
      },
      {
        name: 'get_drucksache',
        description: 'Retrieve the full detail record of a single Drucksache (printed document) by its numeric id.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'Drucksache id — numeric identifier as a string (e.g. "20/123456")',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'search_plenarprotokolle',
        description: 'Search plenary meeting transcripts (Plenarprotokolle) by keyword and/or date range.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Free-text search term',
            },
            date_from: {
              type: 'string',
              description: 'Start date filter in YYYY-MM-DD format',
            },
            date_to: {
              type: 'string',
              description: 'End date filter in YYYY-MM-DD format',
            },
            cursor: {
              type: 'string',
              description: 'Pagination cursor returned from a prior page response',
            },
            num: {
              type: 'number',
              description: 'Number of results to return (1–200, default 50)',
            },
          },
        },
      },
      {
        name: 'get_plenarprotokoll',
        description: 'Retrieve the full detail record of a single plenary protocol by its id.',
        inputSchema: {
          type: 'object',
          properties: {
            id: {
              type: 'string',
              description: 'Plenarprotokoll id as returned by search_plenarprotokolle',
            },
          },
          required: ['id'],
        },
      },
      {
        name: 'search_persons',
        description: 'Search people referenced in DIP parliamentary proceedings: members of parliament, ministers, witnesses, and other named persons.',
        inputSchema: {
          type: 'object',
          properties: {
            query: {
              type: 'string',
              description: 'Name fragment to search for (e.g. "Scholz", "Habeck")',
            },
            cursor: {
              type: 'string',
              description: 'Pagination cursor returned from a prior page response',
            },
            num: {
              type: 'number',
              description: 'Number of results to return (1–200, default 50)',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_activities':
          return this.searchActivities(args);
        case 'search_drucksachen':
          return this.searchDrucksachen(args);
        case 'get_drucksache':
          return this.getDrucksache(args);
        case 'search_plenarprotokolle':
          return this.searchPlenarprotokolle(args);
        case 'get_plenarprotokoll':
          return this.getPlenarprotokoll(args);
        case 'search_persons':
          return this.searchPersons(args);
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

  // ── Private helpers ──────────────────────────────────────────────────────────

  private async dipQuery(
    path: string,
    args: Record<string, unknown>,
    extraKeys: string[],
  ): Promise<ToolResult> {
    const params = new URLSearchParams({
      apikey: this.apiKey,
      format: (args.format as string) ?? 'json',
    });
    // DIP requires this filter to be set; use epoch start as open lower bound
    params.set('f.aktualisiert.start', '1970-01-01T00:00:00.000+00:00');
    if (args.query) params.set('f.titel', String(args.query));
    if (args.date_from) params.set('f.datum.start', String(args.date_from));
    if (args.date_to) params.set('f.datum.end', String(args.date_to));
    if (args.cursor) params.set('cursor', String(args.cursor));
    if (args.num !== undefined) {
      params.set('size', String(Math.min(200, Math.max(1, args.num as number))));
    }
    for (const k of extraKeys) {
      if (args[k]) params.set(`f.${k}`, String(args[k]));
    }
    return this.dipGet(`${path}?${params.toString()}`);
  }

  private async dipGet(pathOrUrl: string): Promise<ToolResult> {
    const url = pathOrUrl.startsWith('http')
      ? pathOrUrl
      : `${this.baseUrl}${pathOrUrl}`;
    // Append apikey + format if not already present (detail endpoints)
    const finalUrl =
      url.includes('apikey=')
        ? url
        : `${url}${url.includes('?') ? '&' : '?'}apikey=${encodeURIComponent(this.apiKey)}&format=json`;

    const response = await this.fetchWithRetry(finalUrl, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (response.status === 401 || response.status === 403) {
      return {
        content: [{ type: 'text', text: 'Bundestag DIP: unauthorized — check your API key' }],
        isError: true,
      };
    }
    if (response.status === 404) {
      return {
        content: [{ type: 'text', text: 'Bundestag DIP: record not found (404)' }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Bundestag DIP API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }

    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }

  private requireString(args: Record<string, unknown>, key: string, example: string): string {
    const v = args[key];
    if (typeof v !== 'string' || !v.trim()) {
      throw new Error(`Required argument "${key}" is missing or empty. Pass a string like ${example}.`);
    }
    return v;
  }

  // ── Tool implementations ────────────────────────────────────────────────────

  private async searchActivities(args: Record<string, unknown>): Promise<ToolResult> {
    return this.dipQuery('/aktivitaet', args, ['ressort', 'descriptor']);
  }

  private async searchDrucksachen(args: Record<string, unknown>): Promise<ToolResult> {
    return this.dipQuery('/drucksache', args, ['drucksachentyp']);
  }

  private async getDrucksache(args: Record<string, unknown>): Promise<ToolResult> {
    const id = this.requireString(args, 'id', '"20/123456"');
    return this.dipGet(`/drucksache/${encodeURIComponent(id)}`);
  }

  private async searchPlenarprotokolle(args: Record<string, unknown>): Promise<ToolResult> {
    return this.dipQuery('/plenarprotokoll', args, []);
  }

  private async getPlenarprotokoll(args: Record<string, unknown>): Promise<ToolResult> {
    const id = this.requireString(args, 'id', '"20/123"');
    return this.dipGet(`/plenarprotokoll/${encodeURIComponent(id)}`);
  }

  private async searchPersons(args: Record<string, unknown>): Promise<ToolResult> {
    return this.dipQuery('/person', args, []);
  }
}

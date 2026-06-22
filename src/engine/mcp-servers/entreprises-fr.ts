/**
 * Entreprises FR MCP Adapter — French Companies Registry
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://recherche-entreprises.api.gouv.fr
// Auth: none (French government open API)
// Docs: https://recherche-entreprises.api.gouv.fr/documentation
// Category: business
// Rate limits: none stated; public keyless API

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://recherche-entreprises.api.gouv.fr';

export class EntreprisesFrMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('EntreprisesFrMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'entreprises-fr',
      displayName: 'Entreprises FR (French Companies)',
      version: '1.0.0',
      category: 'business',
      keywords: [
        'france', 'french companies', 'entreprises', 'siren', 'siret', 'sirene',
        'insee', 'inpi', 'rge', 'ape', 'naf', 'legal entity', 'business registry',
        'french business', 'établissements', 'directors', 'financials',
      ],
      toolNames: ['search', 'get_enterprise', 'nearby'],
      description:
        'French Companies Registry: full-text search and geo-lookup across French legal units via the government recherche-entreprises API. Returns SIREN, denomination, establishments, APE/NAF sector codes, directors, and basic financials. No authentication required.',
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
        description:
          'Full-text search across French legal units. Matches name, sigle, director names, addresses. Returns SIREN, denomination, establishments, sector code (APE/NAF), and basic financials.',
        inputSchema: {
          type: 'object',
          properties: {
            query: { type: 'string', description: 'Free-text — name / director / address' },
            postal_code: { type: 'string', description: 'Filter to a 5-digit French postal code' },
            departement: {
              type: 'string',
              description: 'Filter to a French département (e.g. "75" Paris, "13" Bouches-du-Rhône)',
            },
            ape: { type: 'string', description: 'APE/NAF activity code (e.g. "6201Z" software dev)' },
            employee_range: {
              type: 'string',
              description:
                'Employee count band: NN | 00 | 01 | 02 | 03 | 11 | 12 | 21 | 22 | 31 | 32 | 41 | 42 | 51 | 52 | 53 (Sirene tranche codes)',
            },
            only_active: {
              type: 'boolean',
              description: 'Restrict to currently active units (default true)',
            },
            per_page: { type: 'number', description: 'Page size, 1-25 (default 10)' },
            page: { type: 'number', description: '1-based page (default 1)' },
          },
          required: ['query'],
        },
      },
      {
        name: 'get_enterprise',
        description: 'Fetch a single legal unit with all its establishments by SIREN (9 digits).',
        inputSchema: {
          type: 'object',
          properties: {
            siren: { type: 'string', description: '9-digit SIREN identifier' },
          },
          required: ['siren'],
        },
      },
      {
        name: 'nearby',
        description:
          'List establishments within a radius of a geo coordinate. Useful for "all businesses near …".',
        inputSchema: {
          type: 'object',
          properties: {
            latitude: { type: 'number', description: 'Latitude (WGS84)' },
            longitude: { type: 'number', description: 'Longitude (WGS84)' },
            radius_km: { type: 'number', description: 'Search radius in km, 0.05-50 (default 1)' },
            ape: { type: 'string', description: 'Filter to a specific APE/NAF code' },
            per_page: { type: 'number', description: 'Page size, 1-25 (default 10)' },
            page: { type: 'number', description: '1-based page (default 1)' },
          },
          required: ['latitude', 'longitude'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search':        return this.search(args);
        case 'get_enterprise': return this.getEnterprise(args);
        case 'nearby':        return this.nearby(args);
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

  private async apiGet(path: string, params: URLSearchParams): Promise<ToolResult> {
    const qs = params.toString();
    const url = `${this.baseUrl}${path}${qs ? `?${qs}` : ''}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) {
      return { content: [{ type: 'text', text: 'entreprises-fr: not found' }], isError: true };
    }
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
    if (typeof args.query !== 'string' || !args.query.trim()) {
      return { content: [{ type: 'text', text: 'Required argument "query" is missing or empty.' }], isError: true };
    }
    const params = new URLSearchParams({
      q: args.query,
      page: String(Math.max(1, (args.page as number) ?? 1)),
      per_page: String(Math.min(25, Math.max(1, (args.per_page as number) ?? 10))),
    });
    if (args.postal_code) params.set('code_postal', String(args.postal_code));
    if (args.departement) params.set('departement', String(args.departement));
    if (args.ape) params.set('activite_principale', String(args.ape));
    if (args.employee_range) params.set('tranche_effectif_salarie', String(args.employee_range));
    if (args.only_active !== false) params.set('etat_administratif', 'A');
    return this.apiGet('/search', params);
  }

  private async getEnterprise(args: Record<string, unknown>): Promise<ToolResult> {
    const siren = args.siren;
    if (typeof siren !== 'string' || !/^\d{9}$/.test(siren)) {
      return { content: [{ type: 'text', text: 'Required argument "siren" must be a 9-digit string.' }], isError: true };
    }
    const params = new URLSearchParams({ q: siren, per_page: '1' });
    return this.apiGet('/search', params);
  }

  private async nearby(args: Record<string, unknown>): Promise<ToolResult> {
    const lat = args.latitude;
    const lon = args.longitude;
    if (typeof lat !== 'number' || !Number.isFinite(lat)) {
      return { content: [{ type: 'text', text: 'Required argument "latitude" must be a finite number.' }], isError: true };
    }
    if (typeof lon !== 'number' || !Number.isFinite(lon)) {
      return { content: [{ type: 'text', text: 'Required argument "longitude" must be a finite number.' }], isError: true };
    }
    const params = new URLSearchParams({
      lat: String(lat),
      long: String(lon),
      radius: String(Math.min(50, Math.max(0.05, (args.radius_km as number) ?? 1))),
      page: String(Math.max(1, (args.page as number) ?? 1)),
      per_page: String(Math.min(25, Math.max(1, (args.per_page as number) ?? 10))),
    });
    if (args.ape) params.set('activite_principale', String(args.ape));
    return this.apiGet('/near_point', params);
  }
}

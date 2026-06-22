/**
 * CMS NPI Registry MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official upstream: CMS National Plan & Provider Enumeration System (NPPES)
// Base URL: https://npiregistry.cms.hhs.gov/api
// Auth: none — free public registry of every US healthcare provider NPI
// Docs: https://npiregistry.cms.hhs.gov/help-api
// Quirks:
//   - Must include version=2.1 in every query
//   - At least one non-limit filter is required; the API rejects empty queries
// Category: healthcare
// Rate limits: not published; public government API

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://npiregistry.cms.hhs.gov/api';

export class NpiRegistryMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('NpiRegistryMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'npi-registry',
      displayName: 'CMS NPI Registry',
      version: '1.0.0',
      category: 'healthcare' as const,
      keywords: [
        'npi', 'npi registry', 'nppes', 'cms', 'provider', 'healthcare provider',
        'physician', 'doctor', 'nurse', 'hospital', 'taxonomy', 'medical',
        'individual provider', 'organization provider', 'npi lookup', 'npi search',
        'us healthcare', 'provider directory', 'enumeration',
      ],
      toolNames: ['search', 'get_provider'],
      description: 'CMS NPI Registry: search and retrieve US healthcare provider records by NPI, name, organization, taxonomy, location, or state — free, no authentication required.',
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
          'Search US healthcare providers by any combination of fields. The NPI Registry requires at least one filter besides limit/skip — supply at least one of: number, name, first_name, last_name, organization_name, taxonomy, postal_code, or state.',
        inputSchema: {
          type: 'object',
          properties: {
            number: { type: 'string', description: '10-digit NPI' },
            name: { type: 'string', description: 'Full provider name (use along with npi_type)' },
            first_name: { type: 'string', description: 'Provider first name (individual providers)' },
            last_name: { type: 'string', description: 'Provider last name (individual providers)' },
            organization_name: { type: 'string', description: 'Organization name (NPI-2 providers)' },
            taxonomy: { type: 'string', description: 'Taxonomy code or description (e.g. "Internal Medicine")' },
            city: { type: 'string', description: 'City name' },
            state: { type: 'string', description: 'Two-letter US state code (e.g. "CA")' },
            postal_code: { type: 'string', description: '5-digit ZIP code (or first 3 digits with wildcard "*")' },
            country_code: { type: 'string', description: 'ISO country code — US (default) or other' },
            npi_type: { type: 'string', description: 'NPI-1 (individual provider) | NPI-2 (organization)' },
            address_purpose: { type: 'string', description: 'LOCATION (default) | MAILING | PRIMARY | SECONDARY' },
            limit: { type: 'number', description: 'Results per page: 1–200 (default 10)' },
            skip: { type: 'number', description: 'Zero-based offset for pagination (max 1000)' },
          },
        },
      },
      {
        name: 'get_provider',
        description: 'Fetch a single US healthcare provider record by 10-digit NPI.',
        inputSchema: {
          type: 'object',
          properties: {
            npi: { type: 'string', description: '10-digit NPI number' },
          },
          required: ['npi'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search':
          return this.search(args);
        case 'get_provider':
          return this.getProvider(args);
        default:
          return {
            content: [{ type: 'text', text: `Unknown tool: ${name}` }],
            isError: true,
          };
      }
    } catch (error) {
      return {
        content: [{ type: 'text', text: `Tool execution failed: ${error instanceof Error ? error.message : String(error)}` }],
        isError: true,
      };
    }
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private async search(args: Record<string, unknown>): Promise<ToolResult> {
    const params = new URLSearchParams({ version: '2.1' });

    const fieldMap: Record<string, string> = {
      number:            'number',
      name:              'name',
      first_name:        'first_name',
      last_name:         'last_name',
      organization_name: 'organization_name',
      taxonomy:          'taxonomy_description',
      city:              'city',
      state:             'state',
      postal_code:       'postal_code',
      country_code:      'country_code',
      npi_type:          'enumeration_type',
      address_purpose:   'address_purpose',
    };

    let hasFilter = false;
    for (const [k, v] of Object.entries(args)) {
      if (k === 'limit' || k === 'skip') continue;
      const apiKey = fieldMap[k];
      if (!apiKey) continue;
      if (v === undefined || v === null || String(v).trim() === '') continue;
      params.set(apiKey, String(v));
      hasFilter = true;
    }

    if (!hasFilter) {
      return {
        content: [{ type: 'text', text: 'NPI Registry requires at least one filter (number, name, organization_name, postal_code, state, etc). Provide at least one search criterion.' }],
        isError: true,
      };
    }

    const limit = typeof args.limit === 'number'
      ? Math.min(200, Math.max(1, args.limit))
      : 10;
    const skip = typeof args.skip === 'number'
      ? Math.min(1000, Math.max(0, args.skip))
      : 0;
    params.set('limit', String(limit));
    params.set('skip', String(skip));

    return this.npiGet(`/?${params.toString()}`);
  }

  private async getProvider(args: Record<string, unknown>): Promise<ToolResult> {
    const npi = args.npi;
    if (typeof npi !== 'string' || !npi.trim()) {
      return {
        content: [{ type: 'text', text: 'Required argument "npi" is missing or empty. Pass a 10-digit NPI string.' }],
        isError: true,
      };
    }
    return this.search({ number: npi.trim(), limit: 1 });
  }

  private async npiGet(path: string): Promise<ToolResult> {
    const url = `${this.baseUrl}${path}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `NPI Registry API error: ${response.status} ${errText.slice(0, 200)}` }],
        isError: true,
      };
    }
    const data = await response.json();
    return { content: [{ type: 'text', text: this.truncate(data) }], isError: false };
  }
}

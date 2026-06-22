/**
 * Hipolabs Universities API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: http://universities.hipolabs.com
// Auth: None (free, public API)
// Docs: https://github.com/Hipo/university-domains-list-api
// Category: education
// Rate limits: None documented

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'http://universities.hipolabs.com';

interface RawUniversity {
  name: string;
  country: string;
  alpha_two_code: string;
  'state-province': string | null;
  domains: string[];
  web_pages: string[];
}

export class UniversitiesMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'universities',
      displayName: 'Hipolabs Universities API',
      version: '1.0.0',
      category: 'education',
      keywords: [
        'universities', 'university', 'college', 'higher education',
        'academic', 'school', 'country', 'domain', 'web pages',
        'institution', 'enrollment', 'search',
      ],
      toolNames: ['search_universities'],
      description: 'Hipolabs Universities API: search for universities by name and/or country, returning names, countries, web pages, and domains.',
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
        name: 'search_universities',
        description:
          'Search for universities by name and/or country. Returns university names, countries, web pages, and domains. Both parameters are optional but at least one should be provided.',
        inputSchema: {
          type: 'object',
          properties: {
            name: {
              type: 'string',
              description: 'University name or partial name (e.g., "Harvard", "MIT")',
            },
            country: {
              type: 'string',
              description: 'Country name to filter by (e.g., "United States", "United Kingdom")',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'search_universities':
          return this.searchUniversities(args);
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

  private async searchUniversities(args: Record<string, unknown>): Promise<ToolResult> {
    const nameQuery = args.name as string | undefined;
    const countryQuery = args.country as string | undefined;

    if (!nameQuery && !countryQuery) {
      return {
        content: [{ type: 'text', text: 'At least one of "name" or "country" must be provided' }],
        isError: true,
      };
    }

    const params = new URLSearchParams();
    if (nameQuery) params.set('name', nameQuery);
    if (countryQuery) params.set('country', countryQuery);

    const url = `${BASE_URL}/search?${params.toString()}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });

    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `Hipolabs Universities API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }

    const data = (await response.json()) as RawUniversity[];
    const universities = data.map((raw) => ({
      name: raw.name,
      country: raw.country,
      country_code: raw.alpha_two_code,
      state_province: raw['state-province'] ?? null,
      domains: raw.domains,
      web_pages: raw.web_pages,
    }));

    return {
      content: [{ type: 'text', text: this.truncate({ count: universities.length, universities }) }],
      isError: false,
    };
  }
}

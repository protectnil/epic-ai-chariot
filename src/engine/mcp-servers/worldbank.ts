/**
 * World Bank Data API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official upstream: World Bank Data API v2 (free, no auth)
// Base URL: https://api.worldbank.org/v2
// Docs: https://datahelpdesk.worldbank.org/knowledgebase/articles/889392
// Category: data
// Auth: none (public API)

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.worldbank.org/v2';

export class WorldBankMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'worldbank',
      displayName: 'World Bank Data API',
      version: '1.0.0',
      category: 'data',
      keywords: [
        'world bank', 'worldbank', 'development', 'economics', 'gdp', 'population',
        'co2', 'emissions', 'literacy', 'poverty', 'gini', 'country', 'indicator',
        'time series', 'open data', 'global', 'international', 'macroeconomics',
        'income level', 'region', 'financial data',
      ],
      toolNames: ['get_country', 'get_indicator', 'get_population', 'get_gdp'],
      description: 'World Bank Data API: fetch country metadata (region, income level, capital) and time-series indicator data (GDP, population, CO2 emissions, literacy rate, and more) — free public API, no authentication required.',
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
        name: 'get_country',
        description:
          'Get basic information about a country: full name, region, income level, capital city, and coordinates. Use ISO 3166-1 alpha-2 or alpha-3 country codes (e.g., "US", "GBR", "IN").',
        inputSchema: {
          type: 'object',
          properties: {
            country_code: {
              type: 'string',
              description: 'ISO country code (2 or 3 letters, e.g., "US", "GBR", "CN")',
            },
          },
          required: ['country_code'],
        },
      },
      {
        name: 'get_indicator',
        description:
          'Get time-series values for a World Bank indicator for a specific country. Common indicators: NY.GDP.MKTP.CD (GDP), SP.POP.TOTL (population), EN.ATM.CO2E.KT (CO2 emissions), SE.ADT.LITR.ZS (literacy rate).',
        inputSchema: {
          type: 'object',
          properties: {
            country_code: {
              type: 'string',
              description: 'ISO country code (e.g., "US", "GBR", "CN")',
            },
            indicator: {
              type: 'string',
              description: 'World Bank indicator code (e.g., "NY.GDP.MKTP.CD", "SP.POP.TOTL")',
            },
            date_range: {
              type: 'string',
              description:
                'Year range in format "start:end" (default: 2015:2024). Example: "2000:2023"',
            },
          },
          required: ['country_code', 'indicator'],
        },
      },
      {
        name: 'get_population',
        description:
          'Get total population over time for a country. Shortcut for get_indicator with SP.POP.TOTL.',
        inputSchema: {
          type: 'object',
          properties: {
            country_code: {
              type: 'string',
              description: 'ISO country code (e.g., "US", "GBR", "CN")',
            },
          },
          required: ['country_code'],
        },
      },
      {
        name: 'get_gdp',
        description:
          'Get GDP (current USD) over time for a country. Shortcut for get_indicator with NY.GDP.MKTP.CD.',
        inputSchema: {
          type: 'object',
          properties: {
            country_code: {
              type: 'string',
              description: 'ISO country code (e.g., "US", "GBR", "CN")',
            },
          },
          required: ['country_code'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_country':
          return this.getCountry(args.country_code as string);
        case 'get_indicator':
          return this.getIndicator(
            args.country_code as string,
            args.indicator as string,
            (args.date_range as string) ?? '2015:2024',
          );
        case 'get_population':
          return this.getIndicator(args.country_code as string, 'SP.POP.TOTL', '2015:2024');
        case 'get_gdp':
          return this.getIndicator(args.country_code as string, 'NY.GDP.MKTP.CD', '2015:2024');
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

  private async getCountry(code: string): Promise<ToolResult> {
    const url = `${BASE_URL}/country/${encodeURIComponent(code)}?format=json`;
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
    const data = (await response.json()) as [
      { total?: number; page?: number },
      {
        id: string;
        iso2Code: string;
        name: string;
        region?: { id?: string; value?: string };
        adminregion?: { id?: string; value?: string };
        incomeLevel?: { id?: string; value?: string };
        lendingType?: { id?: string; value?: string };
        capitalCity?: string;
        longitude?: string;
        latitude?: string;
      }[],
    ];
    const meta = data[0];
    const countries = data[1];
    if (!countries || countries.length === 0 || meta?.total === 0) {
      return {
        content: [{ type: 'text', text: `Country not found: ${code}` }],
        isError: true,
      };
    }
    const c = countries[0];
    const result = {
      id: c.id,
      iso2: c.iso2Code,
      name: c.name,
      region: c.region?.value ?? null,
      admin_region: c.adminregion?.value ?? null,
      income_level: c.incomeLevel?.value ?? null,
      lending_type: c.lendingType?.value ?? null,
      capital: c.capitalCity ?? null,
      longitude: c.longitude ? parseFloat(c.longitude) : null,
      latitude: c.latitude ? parseFloat(c.latitude) : null,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getIndicator(
    countryCode: string,
    indicator: string,
    dateRange: string,
  ): Promise<ToolResult> {
    const params = new URLSearchParams({
      format: 'json',
      date: dateRange,
      per_page: '50',
    });
    const url = `${BASE_URL}/country/${encodeURIComponent(countryCode)}/indicator/${encodeURIComponent(indicator)}?${params}`;
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
    const data = (await response.json()) as [
      {
        total?: number;
        page?: number;
        pages?: number;
        per_page?: string;
        lastupdated?: string;
      },
      {
        indicator?: { id?: string; value?: string };
        country?: { id?: string; value?: string };
        countryiso3code?: string;
        date?: string;
        value?: number | null;
        unit?: string;
        obs_status?: string;
        decimal?: number;
      }[] | null,
    ];
    const meta = data[0];
    const values = data[1];
    if (!values || values.length === 0) {
      return {
        content: [{ type: 'text', text: `No data found for indicator "${indicator}" in country "${countryCode}"` }],
        isError: true,
      };
    }
    const firstEntry = values[0];
    const result = {
      country: firstEntry.country?.value ?? countryCode.toUpperCase(),
      country_id: firstEntry.country?.id ?? null,
      indicator_id: firstEntry.indicator?.id ?? indicator,
      indicator_name: firstEntry.indicator?.value ?? null,
      date_range: dateRange,
      total_records: meta?.total ?? values.length,
      last_updated: meta?.lastupdated ?? null,
      data: values
        .filter((v) => v.value !== null && v.value !== undefined)
        .sort((a, b) => (b.date ?? '').localeCompare(a.date ?? ''))
        .map((v) => ({
          year: v.date ?? null,
          value: v.value ?? null,
        })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}

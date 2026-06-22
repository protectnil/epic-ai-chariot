/**
 * Disease.sh COVID-19 API MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://disease.sh/v3/covid-19
// Auth: None required (public API)
// Docs: https://disease.sh/
// Category: science
// Rate limits: None documented

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

interface DiseaseConfig {
  baseUrl?: string;
}

export class DiseaseMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config: DiseaseConfig = {}) {
    super();
    if (!config || typeof config !== 'object') {
      throw new Error('Disease: configuration object is required');
    }
    this.baseUrl = config.baseUrl ?? 'https://disease.sh/v3/covid-19';
  }

  static catalog() {
    return {
      name: 'disease',
      displayName: 'Disease.sh — COVID-19 Statistics',
      version: '1.0.0',
      category: 'science',
      keywords: [
        'disease', 'covid', 'covid-19', 'coronavirus', 'pandemic',
        'cases', 'deaths', 'recovered', 'vaccine', 'vaccination',
        'statistics', 'historical', 'timeline', 'country', 'global',
        'epidemiology', 'public health',
      ],
      toolNames: ['get_global_stats', 'get_country_stats', 'get_historical', 'get_vaccine_stats'],
      description: 'Disease.sh COVID-19 API: global and per-country case/death/recovery statistics, historical timelines, and vaccination coverage — all public, no authentication required.',
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
        name: 'get_global_stats',
        description:
          "Get global COVID-19 statistics. Returns total cases, deaths, recovered, active cases, and today's new cases and deaths.",
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_country_stats',
        description:
          "Get COVID-19 statistics for a specific country. Returns cases, deaths, recovered, active, today's new cases/deaths, and population.",
        inputSchema: {
          type: 'object',
          properties: {
            country: {
              type: 'string',
              description: 'Country name or ISO code (e.g., "USA", "germany", "gb")',
            },
          },
          required: ['country'],
        },
      },
      {
        name: 'get_historical',
        description:
          'Get historical COVID-19 timeline data for a country or globally. Returns daily timeline of cases, deaths, and recoveries.',
        inputSchema: {
          type: 'object',
          properties: {
            country: {
              type: 'string',
              description: 'Country name or "all" for global data (default: "all")',
            },
            days: {
              type: 'number',
              description: 'Number of days of history to return (default: 30)',
            },
          },
        },
      },
      {
        name: 'get_vaccine_stats',
        description:
          'Get COVID-19 vaccination coverage timeline. Returns daily cumulative vaccine doses administered over the last 30 days.',
        inputSchema: {
          type: 'object',
          properties: {
            country: {
              type: 'string',
              description: 'Country name to get vaccine data for. Omit for global totals.',
            },
          },
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_global_stats':
          return this.getGlobalStats();
        case 'get_country_stats':
          return this.getCountryStats(args.country as string);
        case 'get_historical':
          return this.getHistorical(
            (args.country as string | undefined) ?? 'all',
            (args.days as number | undefined) ?? 30,
          );
        case 'get_vaccine_stats':
          return this.getVaccineStats(args.country as string | undefined);
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

  private async getGlobalStats(): Promise<ToolResult> {
    const response = await this.fetchWithRetry(`${this.baseUrl}/all`, {
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

  private async getCountryStats(country: string): Promise<ToolResult> {
    const response = await this.fetchWithRetry(
      `${this.baseUrl}/countries/${encodeURIComponent(country)}`,
      {
        method: 'GET',
        headers: { Accept: 'application/json' },
      },
    );
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

  private async getHistorical(country: string, days: number): Promise<ToolResult> {
    const response = await this.fetchWithRetry(
      `${this.baseUrl}/historical/${encodeURIComponent(country)}?lastdays=${days}`,
      {
        method: 'GET',
        headers: { Accept: 'application/json' },
      },
    );
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

  private async getVaccineStats(country?: string): Promise<ToolResult> {
    const url =
      country != null
        ? `${this.baseUrl}/vaccine/coverage/countries/${encodeURIComponent(country)}?lastdays=30`
        : `${this.baseUrl}/vaccine/coverage?lastdays=30`;

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
}

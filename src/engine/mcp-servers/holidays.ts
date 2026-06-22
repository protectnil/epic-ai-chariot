/**
 * Holidays MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Official REST API: https://date.nager.at/api/v3
// Auth: none (public, no key required)
// Docs: https://date.nager.at
// Category: calendar
// Rate limits: none documented

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://date.nager.at/api/v3';

interface Holiday {
  date: string;
  localName: string;
  name: string;
  countryCode: string;
  fixed: boolean;
  global: boolean;
  counties: string[] | null;
  launchYear: number | null;
  types: string[];
}

interface FormattedHoliday {
  date: string;
  name: string;
  local_name: string;
  global: boolean;
  counties: string[] | null;
  types: string[];
}

function formatHoliday(h: Holiday): FormattedHoliday {
  return {
    date: h.date,
    name: h.name,
    local_name: h.localName,
    global: h.global,
    counties: h.counties ?? null,
    types: h.types,
  };
}

export class HolidaysMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('HolidaysMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'holidays',
      displayName: 'Holidays (Nager.Date)',
      version: '1.0.0',
      category: 'calendar',
      keywords: [
        'holidays', 'public holidays', 'national holidays', 'calendar',
        'country holidays', 'nager', 'date', 'bank holiday', 'federal holiday',
        'ISO 3166', 'country code', 'upcoming holidays',
      ],
      toolNames: ['get_holidays', 'is_today_holiday', 'next_holidays'],
      description: 'Holidays API: look up public holidays by country and year, check if today is a holiday, and list upcoming holidays — free, no authentication required.',
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
        name: 'get_holidays',
        description:
          'Get public holidays for a country and year. Uses ISO 3166-1 alpha-2 country codes (e.g., "US", "GB", "DE").',
        inputSchema: {
          type: 'object',
          properties: {
            country_code: {
              type: 'string',
              description: 'ISO 3166-1 alpha-2 country code (e.g., US, GB, DE, FR)',
            },
            year: {
              type: 'number',
              description: 'The year to retrieve holidays for (e.g., 2025)',
            },
          },
          required: ['country_code', 'year'],
        },
      },
      {
        name: 'is_today_holiday',
        description: 'Check whether today is a public holiday in the given country.',
        inputSchema: {
          type: 'object',
          properties: {
            country_code: {
              type: 'string',
              description: 'ISO 3166-1 alpha-2 country code (e.g., US, GB, DE, FR)',
            },
          },
          required: ['country_code'],
        },
      },
      {
        name: 'next_holidays',
        description: 'Get upcoming public holidays for a country (from today forward).',
        inputSchema: {
          type: 'object',
          properties: {
            country_code: {
              type: 'string',
              description: 'ISO 3166-1 alpha-2 country code (e.g., US, GB, DE, FR)',
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
        case 'get_holidays':   return this.getHolidays(args.country_code as string, args.year as number);
        case 'is_today_holiday': return this.isTodayHoliday(args.country_code as string);
        case 'next_holidays':  return this.nextHolidays(args.country_code as string);
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

  private async getHolidays(countryCode: string, year: number): Promise<ToolResult> {
    const code = countryCode.toUpperCase();
    const url = `${this.baseUrl}/PublicHolidays/${encodeURIComponent(String(year))}/${encodeURIComponent(code)}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) {
      return {
        content: [{ type: 'text', text: `No holiday data for country: "${code}"` }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as Holiday[];
    return {
      content: [{ type: 'text', text: this.truncate({ country_code: code, year, holidays: data.map(formatHoliday) }) }],
      isError: false,
    };
  }

  private async isTodayHoliday(countryCode: string): Promise<ToolResult> {
    const code = countryCode.toUpperCase();
    const url = `${this.baseUrl}/IsTodayPublicHoliday/${encodeURIComponent(code)}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    // 200 = yes, 204 = no, 404 = unknown country
    if (response.status === 404) {
      return {
        content: [{ type: 'text', text: `Unknown country code: "${code}"` }],
        isError: true,
      };
    }
    if (response.status !== 200 && response.status !== 204) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    return {
      content: [{ type: 'text', text: this.truncate({ country_code: code, is_holiday: response.status === 200 }) }],
      isError: false,
    };
  }

  private async nextHolidays(countryCode: string): Promise<ToolResult> {
    const code = countryCode.toUpperCase();
    const url = `${this.baseUrl}/NextPublicHolidays/${encodeURIComponent(code)}`;
    const response = await this.fetchWithRetry(url, {
      method: 'GET',
      headers: { Accept: 'application/json' },
    });
    if (response.status === 404) {
      return {
        content: [{ type: 'text', text: `No holiday data for country: "${code}"` }],
        isError: true,
      };
    }
    if (!response.ok) {
      const errText = await response.text().catch(() => response.statusText);
      return {
        content: [{ type: 'text', text: `API error: ${response.status} ${errText}` }],
        isError: true,
      };
    }
    const data = (await response.json()) as Holiday[];
    return {
      content: [{ type: 'text', text: this.truncate({ country_code: code, upcoming_holidays: data.map(formatHoliday) }) }],
      isError: false,
    };
  }
}

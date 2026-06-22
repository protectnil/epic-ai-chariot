/**
 * Carbon Intensity MCP Adapter — UK Carbon Intensity API
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 */

// Base URL: https://api.carbonintensity.org.uk
// Auth: none (free, unauthenticated public API)
// Docs: https://carbon-intensity.github.io/api-definitions/
// Category: environment
// Rate limits: none published; reasonable use expected

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.carbonintensity.org.uk';

export class CarbonMCPServer extends MCPAdapterBase {
  private readonly baseUrl: string;

  constructor(config?: { baseUrl?: string }) {
    super();
    if (config === null) { throw new Error('CarbonMCPServer: configuration object is required when provided'); }
    this.baseUrl = config?.baseUrl ?? BASE_URL;
  }

  static catalog() {
    return {
      name: 'carbon',
      displayName: 'UK Carbon Intensity API',
      version: '1.0.0',
      category: 'environment',
      keywords: [
        'carbon', 'carbon intensity', 'co2', 'gco2', 'electricity',
        'generation mix', 'fuel type', 'renewable', 'fossil fuel',
        'grid', 'uk energy', 'national grid', 'net zero', 'emissions',
        'solar', 'wind', 'nuclear', 'gas', 'coal', 'hydro', 'biomass',
        'sustainability', 'climate', 'energy mix',
      ],
      toolNames: ['get_intensity', 'get_intensity_by_date', 'get_generation_mix'],
      description: 'UK Carbon Intensity API: real-time national carbon intensity (gCO2/kWh), historical half-hourly data by date, and current electricity generation mix by fuel type — free, unauthenticated.',
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
        name: 'get_intensity',
        description:
          'Get the current UK national carbon intensity. Returns the forecast value (gCO2/kWh), actual measured value, and a qualitative index (very low / low / moderate / high / very high).',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
      {
        name: 'get_intensity_by_date',
        description:
          'Get UK carbon intensity data for every half-hour period of a given date. Returns an array of time-window entries each with forecast and actual gCO2/kWh values.',
        inputSchema: {
          type: 'object',
          properties: {
            date: {
              type: 'string',
              description: 'Date in YYYY-MM-DD format (e.g., 2024-03-15)',
            },
          },
          required: ['date'],
        },
      },
      {
        name: 'get_generation_mix',
        description:
          'Get the current UK electricity generation mix showing the percentage contribution of each fuel type (gas, coal, wind, solar, nuclear, hydro, biomass, imports, etc.).',
        inputSchema: {
          type: 'object',
          properties: {},
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_intensity':         return this.getIntensity();
        case 'get_intensity_by_date': return this.getIntensityByDate(args.date as string);
        case 'get_generation_mix':    return this.getGenerationMix();
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

  private async getIntensity(): Promise<ToolResult> {
    const url = `${this.baseUrl}/intensity`;
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
    const data = (await response.json()) as {
      data: {
        from: string;
        to: string;
        intensity: {
          forecast: number;
          actual: number | null;
          index: string;
        };
      }[];
    };
    const entry = data.data[0];
    if (!entry) {
      return { content: [{ type: 'text', text: 'No intensity data returned' }], isError: true };
    }
    const result = {
      from: entry.from,
      to: entry.to,
      forecast_gco2_per_kwh: entry.intensity.forecast,
      actual_gco2_per_kwh: entry.intensity.actual,
      index: entry.intensity.index,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getIntensityByDate(date: string): Promise<ToolResult> {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(date)) {
      return {
        content: [{ type: 'text', text: 'Date must be in YYYY-MM-DD format' }],
        isError: true,
      };
    }
    const url = `${this.baseUrl}/intensity/date/${encodeURIComponent(date)}`;
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
    const data = (await response.json()) as {
      data: {
        from: string;
        to: string;
        intensity: {
          forecast: number;
          actual: number | null;
          index: string;
        };
      }[];
    };
    const result = {
      date,
      periods: data.data.map((entry) => ({
        from: entry.from,
        to: entry.to,
        forecast_gco2_per_kwh: entry.intensity.forecast,
        actual_gco2_per_kwh: entry.intensity.actual,
        index: entry.intensity.index,
      })),
      count: data.data.length,
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }

  private async getGenerationMix(): Promise<ToolResult> {
    const url = `${this.baseUrl}/generation`;
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
    const data = (await response.json()) as {
      data: {
        from: string;
        to: string;
        generationmix: {
          fuel: string;
          perc: number;
        }[];
      };
    };
    const entry = data.data;
    const result = {
      from: entry.from,
      to: entry.to,
      generation_mix: entry.generationmix.map((g) => ({
        fuel: g.fuel,
        percentage: g.perc,
      })),
    };
    return { content: [{ type: 'text', text: this.truncate(result) }], isError: false };
  }
}

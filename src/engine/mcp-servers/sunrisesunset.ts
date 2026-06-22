/**
 * Sunrise-Sunset MCP Adapter
 * Built on the Epic AI® Intelligence Platform
 * Copyright 2026 protectNIL Inc. Elastic-2.0
 *
 * Upstream: https://api.sunrisesunset.io (free, no auth)
 * Docs: https://sunrisesunset.io/api/
 * Category: weather
 */

import { ToolDefinition, ToolResult } from './types.js';
import { MCPAdapterBase } from './base.js';

const BASE_URL = 'https://api.sunrisesunset.io';

export class SunriseSunsetMCPServer extends MCPAdapterBase {
  constructor() {
    super();
  }

  static catalog() {
    return {
      name: 'sunrisesunset',
      displayName: 'Sunrise-Sunset',
      version: '1.0.0',
      category: 'weather',
      keywords: [
        'sunrise', 'sunset', 'dawn', 'dusk', 'solar noon', 'golden hour',
        'first light', 'last light', 'day length', 'sun times', 'astronomy',
        'latitude', 'longitude', 'timezone', 'utc offset',
      ],
      toolNames: ['get_times', 'get_times_date'],
      description: 'Sunrise-Sunset API: get sunrise, sunset, dawn, dusk, solar noon, golden hour, and day length for any location by latitude/longitude, for today or any specific date.',
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
        name: 'get_times',
        description: "Get today's sunrise, sunset, dawn, dusk, solar noon, and golden hour times for a location.",
        inputSchema: {
          type: 'object',
          properties: {
            lat: { type: 'number', description: 'Latitude of the location (e.g., 40.7128)' },
            lng: { type: 'number', description: 'Longitude of the location (e.g., -74.0060)' },
          },
          required: ['lat', 'lng'],
        },
      },
      {
        name: 'get_times_date',
        description: 'Get sunrise, sunset, dawn, dusk, solar noon, and golden hour times for a specific date at a location.',
        inputSchema: {
          type: 'object',
          properties: {
            lat: { type: 'number', description: 'Latitude of the location (e.g., 40.7128)' },
            lng: { type: 'number', description: 'Longitude of the location (e.g., -74.0060)' },
            date: {
              type: 'string',
              description: 'Date in YYYY-MM-DD format (e.g., "2024-06-21")',
            },
          },
          required: ['lat', 'lng', 'date'],
        },
      },
    ];
  }

  async callTool(name: string, args: Record<string, unknown>): Promise<ToolResult> {
    try {
      switch (name) {
        case 'get_times':      return this.getTimes(args);
        case 'get_times_date': return this.getTimesDate(args);
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

  private async fetchSunTimes(lat: number, lng: number, date?: string): Promise<ToolResult> {
    const params = new URLSearchParams({
      lat: String(lat),
      lng: String(lng),
    });
    if (date) params.set('date', date);

    const url = `${BASE_URL}/json?${params.toString()}`;
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

    const data = await response.json() as { results: unknown; status: string };
    if (data.status !== 'OK') {
      return {
        content: [{ type: 'text', text: `API error: status=${data.status}` }],
        isError: true,
      };
    }

    return { content: [{ type: 'text', text: this.truncate(data.results) }], isError: false };
  }

  private async getTimes(args: Record<string, unknown>): Promise<ToolResult> {
    const lat = args.lat as number;
    const lng = args.lng as number;
    return this.fetchSunTimes(lat, lng);
  }

  private async getTimesDate(args: Record<string, unknown>): Promise<ToolResult> {
    const lat = args.lat as number;
    const lng = args.lng as number;
    const date = args.date as string;
    return this.fetchSunTimes(lat, lng, date);
  }
}
